/**
 * @name curl-8f4608468b890dc-ftp_disconnect
 * @id cpp/curl/8f4608468b890dc/ftp-disconnect
 * @description curl-8f4608468b890dc-lib/ftp.c-ftp_disconnect CVE-2023-27535
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vftpc_4071, Variable vCurl_cfree, ExprStmt target_2, ExprStmt target_3, Function func) {
	exists(DoStmt target_0 |
		target_0.getCondition().(Literal).getValue()="0"
		and target_0.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getExpr().(VariableAccess).getTarget()=vCurl_cfree
		and target_0.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="account"
		and target_0.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vftpc_4071
		and target_0.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="account"
		and target_0.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vftpc_4071
		and target_0.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(6)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(6).getFollowingStmt()=target_0)
		and target_2.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_3.getExpr().(VariableCall).getExpr().(VariableAccess).getLocation().isBefore(target_0.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getExpr().(VariableAccess).getLocation()))
}

predicate func_1(Variable vftpc_4071, Variable vCurl_cfree, ExprStmt target_4, Function func) {
	exists(DoStmt target_1 |
		target_1.getCondition().(Literal).getValue()="0"
		and target_1.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getExpr().(VariableAccess).getTarget()=vCurl_cfree
		and target_1.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="alternative_to_user"
		and target_1.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vftpc_4071
		and target_1.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="alternative_to_user"
		and target_1.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vftpc_4071
		and target_1.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(7)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(7).getFollowingStmt()=target_1)
		and target_1.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_4.getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(Variable vftpc_4071, ExprStmt target_2) {
		target_2.getExpr().(FunctionCall).getTarget().hasName("freedirs")
		and target_2.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vftpc_4071
}

predicate func_3(Variable vftpc_4071, Variable vCurl_cfree, ExprStmt target_3) {
		target_3.getExpr().(VariableCall).getExpr().(VariableAccess).getTarget()=vCurl_cfree
		and target_3.getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="entrypath"
		and target_3.getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vftpc_4071
}

predicate func_4(Variable vftpc_4071, Variable vCurl_cfree, ExprStmt target_4) {
		target_4.getExpr().(VariableCall).getExpr().(VariableAccess).getTarget()=vCurl_cfree
		and target_4.getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="prevpath"
		and target_4.getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vftpc_4071
}

from Function func, Variable vftpc_4071, Variable vCurl_cfree, ExprStmt target_2, ExprStmt target_3, ExprStmt target_4
where
not func_0(vftpc_4071, vCurl_cfree, target_2, target_3, func)
and not func_1(vftpc_4071, vCurl_cfree, target_4, func)
and func_2(vftpc_4071, target_2)
and func_3(vftpc_4071, vCurl_cfree, target_3)
and func_4(vftpc_4071, vCurl_cfree, target_4)
and vftpc_4071.getType().hasName("ftp_conn *")
and vCurl_cfree.getType().hasName("curl_free_callback")
and vftpc_4071.(LocalVariable).getFunction() = func
and not vCurl_cfree.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
