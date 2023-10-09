### Tuned profile to be used for IBM Storage Scale Erasure Code Edition (ECE)


NOTE: How to add profile to the system, refer to [Chapter 3. Customizing TuneD profiles](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/8/html/monitoring_and_managing_system_status_and_performance/customizing-tuned-profiles_monitoring-and-managing-system-status-and-performance)




**Instructions**
- If tuned was not enabled, enable it: ***systemctl enable tuned***
- If tuned was not active (running), start it: ***systemctl start tuned***
- If IBM Storage Scale Erasure Code Edition to be installed is
  - 5.1.9 and subsequent version
    - Copy the directory which has the suffix ***_RH\**** to the ***/etc/tuned/*** directory with new directory named as ***/etc/tuned/storagescale-ece***
    - Apply the profile: ***tuned-adm profile storagescale-ece***
  - 5.1.8 and previous version
    - Copy the directory which has the suffix ***_RH\**** to the ***/etc/tuned/*** directory with new directory named as ***/etc/tuned/spectrumscale-ece***
    - Apply the profile: ***tuned-adm profile spectrumscale-ece***
- Verify current profile against system settings: ***tuned-adm verify***
- Investigate log mentioned by output of 'tuned-adm verify' if hit issue
