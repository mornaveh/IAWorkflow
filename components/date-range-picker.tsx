"use client"

import { useState } from "react"
import { X } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"

interface DateRangePickerProps {
  onDateRangeSelect: (startDate: string, endDate: string) => void
  onClose: () => void
}

export function DateRangePicker({ onDateRangeSelect, onClose }: DateRangePickerProps) {
  const [startDate, setStartDate] = useState("")
  const [endDate, setEndDate] = useState("")

  const handleApply = () => {
    if (startDate && endDate) {
      onDateRangeSelect(startDate, endDate)
      onClose()
    }
  }

  const handleClear = () => {
    setStartDate("")
    setEndDate("")
  }

  return (
    <div className="p-4 space-y-4 w-80">
      <div className="flex items-center justify-between">
        <h3 className="font-medium">Select Date Range</h3>
        <Button variant="ghost" size="sm" onClick={onClose}>
          <X className="w-4 h-4" />
        </Button>
      </div>

      <div className="space-y-3">
        <div>
          <Label htmlFor="start-date" className="text-sm font-medium">
            Start Date
          </Label>
          <Input
            id="start-date"
            type="date"
            value={startDate}
            onChange={(e) => setStartDate(e.target.value)}
            className="mt-1"
          />
        </div>

        <div>
          <Label htmlFor="end-date" className="text-sm font-medium">
            End Date
          </Label>
          <Input
            id="end-date"
            type="date"
            value={endDate}
            onChange={(e) => setEndDate(e.target.value)}
            className="mt-1"
          />
        </div>
      </div>

      <div className="flex gap-2 pt-2">
        <Button variant="outline" size="sm" onClick={handleClear}>
          Clear
        </Button>
        <Button size="sm" onClick={handleApply} disabled={!startDate || !endDate}>
          Apply
        </Button>
      </div>
    </div>
  )
}
