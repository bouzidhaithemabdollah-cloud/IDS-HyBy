class Engine:
      def __init__(self,detectors ,on_alert=print):
            self.detectors=detectors
            self.on_alert=on_alert
      def __call__(self, flow):
         for detector in self.detectors:
            alert=detector.check(flow)
            if alert:
                self.on_alert(alert)


 