package com.chargeguardian.android.database

import androidx.room.*

@Entity(tableName = "charge_log")
data class ChargeLog(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    val merchant: String,
    val method: String,
    val url: String,
    val confirmed: Boolean,
    val timestamp: Long
)

@Dao
interface ChargeLogDao {
    @Query("SELECT * FROM charge_log ORDER BY timestamp DESC")
    suspend fun getAll(): List<ChargeLog>

    @Query("SELECT * FROM charge_log WHERE confirmed = 1 ORDER BY timestamp DESC")
    suspend fun getConfirmed(): List<ChargeLog>

    @Query("SELECT * FROM charge_log WHERE confirmed = 0 ORDER BY timestamp DESC")
    suspend fun getCancelled(): List<ChargeLog>

    @Query("SELECT COUNT(*) FROM charge_log WHERE confirmed = 1")
    suspend fun getConfirmedCount(): Int

    @Query("SELECT COUNT(*) FROM charge_log WHERE confirmed = 0")
    suspend fun getCancelledCount(): Int

    @Insert
    suspend fun insert(log: ChargeLog)

    @Query("DELETE FROM charge_log WHERE timestamp < :beforeTimestamp")
    suspend fun deleteOlderThan(beforeTimestamp: Long)
}

@Database(entities = [ChargeLog::class], version = 1, exportSchema = false)
abstract class ChargeGuardianDatabase : RoomDatabase() {
    abstract fun chargeLogDao(): ChargeLogDao

    companion object {
        @Volatile
        private var INSTANCE: ChargeGuardianDatabase? = null

        fun getInstance(context: android.content.Context): ChargeGuardianDatabase {
            return INSTANCE ?: synchronized(this) {
                val instance = Room.databaseBuilder(
                    context.applicationContext,
                    ChargeGuardianDatabase::class.java,
                    "chargeguardian-db"
                ).build()
                INSTANCE = instance
                instance
            }
        }
    }
}
