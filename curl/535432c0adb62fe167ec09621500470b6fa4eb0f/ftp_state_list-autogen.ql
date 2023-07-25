/**
 * @name curl-535432c0adb62fe167ec09621500470b6fa4eb0f-ftp_state_list
 * @id cpp/curl/535432c0adb62fe167ec09621500470b6fa4eb0f/ftp-state-list
 * @description curl-535432c0adb62fe167ec09621500470b6fa4eb0f-lib/ftp.c-ftp_state_list CVE-2018-1000120
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, Literal target_0) {
		target_0.getValue()="0"
		and not target_0.getValue()="1"
		and target_0.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("Curl_urldecode")
		and target_0.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(Literal).getValue()="0"
		and target_0.getEnclosingFunction() = func
}

from Function func, Literal target_0
where
func_0(func, target_0)
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
