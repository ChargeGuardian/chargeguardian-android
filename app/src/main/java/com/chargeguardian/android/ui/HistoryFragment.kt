package com.chargeguardian.android.ui

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.fragment.app.Fragment
import androidx.lifecycle.lifecycleScope
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.chargeguardian.android.R
import com.chargeguardian.android.database.ChargeGuardianDatabase
import com.chargeguardian.android.database.ChargeLog
import kotlinx.coroutines.launch
import java.text.SimpleDateFormat
import java.util.*

class HistoryFragment : Fragment() {

    private lateinit var recyclerView: RecyclerView
    private lateinit var emptyView: TextView
    private lateinit var statsView: TextView

    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?): View? {
        return inflater.inflate(R.layout.fragment_history, container, false)
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        recyclerView = view.findViewById(R.id.historyRecyclerView)
        emptyView = view.findViewById(R.id.emptyHistory)
        statsView = view.findViewById(R.id.statsView)

        recyclerView.layoutManager = LinearLayoutManager(requireContext())
        loadHistory()
    }

    private fun loadHistory() {
        lifecycleScope.launch {
            val db = ChargeGuardianDatabase.getInstance(requireContext())
            val logs = db.chargeLogDao().getAll()
            val confirmed = db.chargeLogDao().getConfirmedCount()
            val cancelled = db.chargeLogDao().getCancelledCount()

            statsView.text = "✅ $confirmed confirmed · 🚫 $cancelled blocked"

            if (logs.isEmpty()) {
                emptyView.visibility = View.VISIBLE
                recyclerView.visibility = View.GONE
            } else {
                emptyView.visibility = View.GONE
                recyclerView.visibility = View.VISIBLE
                recyclerView.adapter = HistoryAdapter(logs)
            }
        }
    }

    inner class HistoryAdapter(private val logs: List<ChargeLog>) :
        RecyclerView.Adapter<HistoryAdapter.ViewHolder>() {

        inner class ViewHolder(view: View) : RecyclerView.ViewHolder(view) {
            val merchantText: TextView = view.findViewById(R.id.merchantText)
            val methodText: TextView = view.findViewById(R.id.methodText)
            val dateText: TextView = view.findViewById(R.id.dateText)
            val statusText: TextView = view.findViewById(R.id.statusText)
        }

        override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
            val view = LayoutInflater.from(parent.context)
                .inflate(R.layout.item_history, parent, false)
            return ViewHolder(view)
        }

        override fun onBindViewHolder(holder: ViewHolder, position: Int) {
            val log = logs[position]
            holder.merchantText.text = log.merchant
            holder.methodText.text = log.method.replace("_", " ").replaceFirstChar { it.uppercase() }
            holder.dateText.text = SimpleDateFormat("MMM dd, HH:mm", Locale.getDefault()).format(Date(log.timestamp))
            holder.statusText.text = if (log.confirmed) "✅ Confirmed" else "🚫 Blocked"
        }

        override fun getItemCount() = logs.size
    }
}
