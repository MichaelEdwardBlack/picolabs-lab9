ruleset com.blacklite.krl.gossip.node {
  meta {
    shares __testing, test, getOptimalState, getPeer
    
    use module io.picolabs.subscription alias subscriptions
    use module io.picolabs.wrangler alias wrangler
  }
  global {
    __testing = { "queries":
      [ { "name": "__testing" }
      , { "name": "test" }
      , { "name": "getOptimalState" }
      , { "name": "getPeer" }
      //, { "name": "entry", "args": [ "key" ] }
      ] , "events":
      [ { "domain": "gossip", "type": "start" }
      , { "domain": "gossip", "type": "kill" }
      , { "domain": "gossip", "type": "set_frequency", "args": [ "seconds" ] }
      //, { "domain": "d2", "type": "t2", "attrs": [ "a1", "a2" ] }
      ]
    }
    test = function() {
      state = getOptimalState();
      self = state{"self"};
      nodes = state{"nodes"};
      self.keys().filter(function(x) {
        self{x} != {}
      })
    }
    
    getChannelFromSensorId = function(sensorId) {
      ent:gossip_subs{sensorId}
    }
    
    messageId = function(number = 0) {
      <<#{meta:picoId}:#{number}>>
    }
    
    getOptimalState = function() {
      self = ent:state{meta:picoId};
      nodes = ent:state.delete(meta:picoId);
      
      nodesNeedFromMe = nodes.map(function(seen, nodeId) {
        increment = seen.filter(function(sequence, id) {
          self{id} > sequence
        });
        
        missing = self.filter(function(sequence, id) {
          seen{id}.isnull()
        });
        
        needs = increment.put(missing);
        needs
      });
      
      myNeedsFromNodes = nodes.map(function(seen, nodeId) {
        seen.filter(function(sequence, id) {
          self{id}.isnull() || self{id} < sequence
        })
      });
      
      {"self": myNeedsFromNodes, "nodes": nodesNeedFromMe }
    }
    
    getPeer = function(state = getOptimalState()) {
      self = state{"self"};
      nodes = state{"nodes"};
      sIds = self.keys().filter(function(x) {
        self{x} != {}
      });
      nIds = nodes.keys().filter(function(x) {
        nodes{x} != {}
      });
      
      (sIds.length() == 0 && nIds.length() == 0) => null |
      (sIds.length() > 0) => sIds[random:integer(sIds.length() - 1)]
      | nIds[random:integer(nIds.length() - 1)];
    }
    
    prepareMessage = function(state, sensorId) {
      // 0=rumor 1=seen
      i = random:integer(1);
      (subscriber.isnull()) => null | 
      (i == 0) => rumorMessage(sensorId) | seenMessage()
    }
    
    rumorMessage = function(sensorId) {
      sequence = ent:messages{sensorId}.keys().sort("numeric").head();
      ent:messages{[sensorId, sequence]}
    }
    
    seenMessage = function() {
      ent:state
    }
    
    getUpdatedSequence = function(sensorId, sequence) {
      sequences = ent:messages{sensorId}.keys().append(sequence).sort("numeric");
      sequences.reduce(function(a, b) {
        (b == a + 1) => b | a
      });
    }
    
  }
  
  rule init {
    select when wrangler ruleset_added where rids >< meta:rid
    pre {
      s1 = {
          "ABCD-1234-ABCD-1234-ABCD-125A": 3,
          "ABCD-1234-ABCD-1234-ABCD-129B": 5,
          "ABCD-1234-ABCD-1234-ABCD-123C": 10
      }
      s2 = {
          "ABCD-1234-ABCD-1234-ABCD-125A": 3,
          "ABCD-1234-ABCD-1234-ABCD-129B": 4,
          "ABCD-1234-ABCD-1234-ABCD-123C": 10
      }
      s3 = {
          "ABCD-1234-ABCD-1234-ABCD-125A": 3,
          "ABCD-1234-ABCD-1234-ABCD-129B": 5,
          "ABCD-1234-ABCD-1234-ABCD-123C": 11
      }
    }
    fired {
      ent:messages := {};
      ent:frequency := 60
      ent:state{"ABCD-1234-ABCD-1234-ABCD-125A"} := s1;
      ent:state{"ABCD-1234-ABCD-1234-ABCD-129B"} := s2;
      ent:state{"ABCD-1234-ABCD-1234-ABCD-123C"} := s3;
      ent:state{meta:picoId} := s1
      
    }
  }
  
  rule start_heartbeat {
    select when gossip start
    fired {
      raise gossip event "hearbeat"
    }
  }
  
  rule kill_heartbeat {
    select when gossip kill
    foreach schedule:list() setting(x)
    pre {
      id = x{"id"}
    }
    schedule:remove(id);
  }
  
  rule gossip_heartbeat {
    select when gossip heartbeat
    pre {
      state = getOptimalState()
      subscriber = getPeer(state)
      m = prepareMessage(state, subscriber)
    }
    
    if subscriber then every {
      send(subscriber, m);
      update(state)
    }
    fired {
      schedule gossip event "hearbeat" at time:add(time:now(), {"seconds": ent:frequency})
    }
  }
  
  rule set_gossip_frequency {
    select when gossip set_frequency
    pre {
      seconds = event:attr("seconds")
    }
    if seconds then noop()
    fired {
      ent:frequency := seconds.as("Number")
    }
  }
  
  rule gossip_rumor {
    select when gossip rumor
    pre {
      message = event:attr("message")
      id = message{"SensorID"}
      sequence = message{"MessageID"}.split(re#:#)[1]
      updatedSequence = getUpdatedSequence(id, sequence)
    }
    fired {
      ent:gossip_subs{id} := meta:eci
      ent:messages{[id, sequence]} := message
      ent:state{[meta:picoId, id]} := updatedSequence
    }
  }
  
  rule gossip_seen {
    select when gossip seen
    foreach event:attr("state") setting(seen,sensorId)
    pre {
      needs = seen.filter(function(sequence, id) {
        ent:state{[sensorId, id]} > sequence
      });
      missing = ent:state{[sensorId]}.filter(function(sequence, id) {
        seen{id}.isnull()
      })
    }
  }
  
  rule connect {
    select when gossip connect
    pre {
      sensor_eci = event:attr("sensor_eci");
    }
    event:send({ 
     "eci": meta:eci, "eid": "subscription",
     "domain": "wrangler", "type": "subscription",
     "attrs": { "name": "gossip",
                "coid": "gossip",
                "picoId": meta:picoId,
                "Rx_role": "node",
                "Tx_role": "node",
                "channel_type": "subscription",
                "wellKnown_Tx": sensor_eci }
    })
  }
  
  rule auto_accept {
    select when wrangler inbound_pending_subscription_added where coid == "gossip"
    pre {
      picoId = event:attr("picoId");
      attributes = event:attrs.klog("inbound subscription attributes: ")
    }
    always {
      raise wrangler event "pending_subscription_approval"
        attributes attributes;
      ent:gossip_subs{picoId} := event:attr("Tx");
    }
  }
  
}
