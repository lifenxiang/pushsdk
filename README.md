# Build

CMake is used to build the SDK. Build is possible on mac, ubuntu/debian linux, windows and cross compilation for raspberry pi on linux.

- CMake options:
  - -DENABLE_SHARED: Build shared library.
  - -DENABLE_STATIC: Build static library.
  - -DENABLE_APPS: Build applications.

- Build on mac

  - Install prerequisites

    ```bash
    brew install autoconf automake libtool shtool pkg-config gettext cmake
    ```

  - Compile

    ```bash
    cd ${YOUR_PATH}/Elastos.NET.PushNotification.SDK
    mkdir -p build/mac && cd build/mac
    cmake ../..
    make && make install
    ```

- Build on ubuntu/debian linux

  - Install prerequisites

    ```bash
    sudo apt-get update
    sudo apt-get install -f build-essential autoconf automake autopoint libtool flex bison libncurses5-dev cmake
    ```

  - Compile

    ```bash
    cd ${YOUR_PATH}/Elastos.NET.PushNotification.SDK
    mkdir -p build/linux && cd build/linux
    cmake ../..
    make && make install
    ```

- Build on windows

  - Install prerequisites

    Install Visual Studio 2017 and "Desktop development with C++" Workload.

  - Compile

    ```powershell
    cd ${YOUR_PATH}/Elastos.NET.PushNotification.SDK
    mkdir build/win
    cd build/win
    cmake -G "NMake Makefiles" -DCMAKE_INSTALL_PREFIX=outputs ..\..
    nmake
    nmake install
    ```

- Cross compilation for raspberry pi on linux

  - Install prerequisites

    Download [raspberry pi toolchain](https://github.com/raspberrypi/tools).

  - Compile

    ```bash
    cd ${YOUR_PATH}/Elastos.NET.PushNotification.SDK
    mkdir -p build/rpi && cd build/rpi
    cmake -DCMAKE_INSTALL_PRFIX=outputs -DRPI_TOOLCHAIN_HOME=${YOUR-RASPBERRYPI-TOOLCHAIN-HOME} -DCMAKE_TOOLCHAIN_FILE=../../cmake/RPiToolchain.cmake ../..
    make && make install
    ```

# Definitions

- Push Service Provider(PSP)：A push service provider can push data to a device. Only FCM and APNs are supported at present. FCM and APNs projects are identified by project ID and certificate, respectively.
- Scope：A set of PSPs, identiified by scope name.
- App instance：Specific app instance runs on specific Android or IOS device. Android and IOS app instances are identified by reg ID and dev token, respectively.
- Subscriber：A set of app instances, identified by event ID.
# Example
- Admin deploying PSPs
  - For FCM
    Admin obtains project ID **"push example project id"** and server key **"push example server key"** from firebase console.([Find the project ID](https://firebase.google.com/docs/projects/learn-more#find_the_project_id)) ([Firebase messaging, where to get Server Key?](https://stackoverflow.com/questions/37427709/firebase-messaging-where-to-get-server-key))
  - For APNs
    Admin obtains p12 certificate **push_example_certificate.p12** from Apple. ([How to generate a P12 Apple push certificate in 3 minutes](https://www.youtube.com/watch?v=AZzi71xs7_s&t=72s))
- Admin deploying push server on **pushexample.com:9898** 
  - Admin installs Uniqush. ([Installing Uniqush and its Dependencies](https://uniqush.org/documentation/install.html))
  - Admin configures Uniqush to set addr option in WebFrontend section to 0.0.0.0:9898. ([Uniqush Configuration](https://uniqush.org/documentation/config.html)) 
  - Admin converts **push_example_certificate.p12** into two pem files **push_example_certificate.pem** and **push_example_private_key.pem** and put them on push server under **/etc/push**. ([Export APNS keys to .PEM format](http://tleyden.github.io/blog/2016/02/03/setting-up-uniqush-with-apns))
- Admin configuring scope **"push example scope"** on push server
  - For FCM
    ```c
    push_server_t push_server = {
        .host = "pushexample.com",
        .port = "9898"
    };
    registered_project_key_t project_key = {
        .service_type = "fcm",
        .project_id   = "push example project id",
        .api_key      = "push example server key"
    };
    
    register_push_service(&push_server, "push example scope", 
                          (const registered_data_t *)&project_key);
    ```
  - For APNs
    ```c
    push_server_t push_server = {
        .host = "pushexample.com",
        .port = "9898"
    };
    registered_certificate_t certificate = {
        .service_type     = "apns",
        .certificate_path = "/etc/push/push_example_certificate.pem",
        .private_key_path = "/etc/push/push_example_private_key.pem"
    };
    
    register_push_service(&push_server, "push example scope", 
                          (const registered_data_t *)&certificate);
    ```
- Admin deploying app server
- App user installing app instance
- App instance obtaining reg ID(for Andorid) **"push example reg id"** and dev token(for IOS) **"push example dev token"** from PSP. 
  ([Set up a Firebase Cloud Messaging client app on Android](https://firebase.google.com/docs/cloud-messaging/android/client))
  ([Apple user notification](https://developer.apple.com/documentation/usernotifications))
- App instance subscribing scope **"push example scope"** with event ID **"push example subscriber"** from push server
  - For Android
    ```c
    push_server_t push_server = {
        .host = "pushexample.com",
        .port = "9898"
    };
    subscribed_project_id_t project_id = {
        .service_type = "fcm",
        .register_id  = "push example reg id"
    };
    
    subscribe_push_service(&push_server, "push example scope", "push example subscriber",
                           (const subscribed_cookie_t *)&project_id);
    ```
  - For IOS
    ```c
    push_server_t push_server = {
        .host = "pushexample.com",
        .port = "9898"
    };
    subscribed_dev_token_t dev_token = {
        .service_type = "apns",
        .dev_token    = "push example dev token"
    };
    
    subscribe_push_service(&push_server, "push example scope", "push example subscriber",
                           (const subscribed_cookie_t *)&dev_token);
    ```
- App instance notifying app server of its event ID **"push example subscriber"**
- App server requesting push server to push message **"push example message"** to subscriber **"push example subscriber"** using  scope **"push example scope"**
  ```c
  push_server_t push_server = {
      .host = "pushexample.com",
      .port = "9898"
  };
  
  send_push_message(&push_server, "push example scope", 
                    "push example subscriber", "push example message");
  ```
  
