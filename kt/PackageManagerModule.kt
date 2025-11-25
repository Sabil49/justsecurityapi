// android/app/src/main/java/com/sabil/justsecurity/PackageManagerModule.kt
package com.sabil.justsecurity

import android.content.pm.PackageManager
import com.facebook.react.bridge.*

class PackageManagerModule(reactContext: ReactApplicationContext) : 
    ReactContextBaseJavaModule(reactContext) {

    override fun getName() = "PackageManager"

    @ReactMethod
    fun getInstalledApps(promise: Promise) {
        try {
            val pm = reactApplicationContext.packageManager
            val packages = pm.getInstalledApplications(PackageManager.GET_META_DATA)
            
            val apps = WritableNativeArray()
            for (packageInfo in packages) {
                val app = WritableNativeMap()
                app.putString("packageName", packageInfo.packageName)
                app.putString("appName", pm.getApplicationLabel(packageInfo).toString())
                
                // Get permissions
                val permissions = WritableNativeArray()
                try {
                    val pkgInfo = pm.getPackageInfo(
                        packageInfo.packageName, 
                        PackageManager.GET_PERMISSIONS
                    )
                    pkgInfo.requestedPermissions?.forEach { perm ->
                        permissions.pushString(perm)
                    }
                } catch (e: Exception) {
                    // Handle exception
                }
                
                app.putArray("permissions", permissions)
                apps.pushMap(app)
            }
            
            promise.resolve(apps)
        } catch (e: Exception) {
            promise.reject("ERROR", e.message)
        }
    }
}