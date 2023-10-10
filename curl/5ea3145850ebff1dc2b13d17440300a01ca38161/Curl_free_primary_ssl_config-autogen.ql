/**
 * @name curl-5ea3145850ebff1dc2b13d17440300a01ca38161-Curl_free_primary_ssl_config
 * @id cpp/curl/5ea3145850ebff1dc2b13d17440300a01ca38161/Curl-free-primary-ssl-config
 * @description curl-5ea3145850ebff1dc2b13d17440300a01ca38161-lib/vtls/vtls.c-Curl_free_primary_ssl_config CVE-2021-22924
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vsslc_179, Variable vCurl_cfree, ExprStmt target_2, ExprStmt target_3, ExprStmt target_4, Function func) {
	exists(DoStmt target_0 |
		target_0.getCondition().(Literal).getValue()="0"
		and target_0.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getExpr().(VariableAccess).getTarget()=vCurl_cfree
		and target_0.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="issuercert"
		and target_0.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsslc_179
		and target_0.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="issuercert"
		and target_0.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsslc_179
		and target_0.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(2)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(2).getFollowingStmt()=target_0)
		and target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_4.getExpr().(VariableCall).getExpr().(VariableAccess).getLocation().isBefore(target_0.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getExpr().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vsslc_179, Variable vCurl_cfree, ExprStmt target_5, ExprStmt target_6, ExprStmt target_7, Function func) {
	exists(DoStmt target_1 |
		target_1.getCondition().(Literal).getValue()="0"
		and target_1.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getExpr().(VariableAccess).getTarget()=vCurl_cfree
		and target_1.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="issuercert_blob"
		and target_1.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsslc_179
		and target_1.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="issuercert_blob"
		and target_1.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsslc_179
		and target_1.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(11)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(11).getFollowingStmt()=target_1)
		and target_5.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_1.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_6.getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_7.getExpr().(VariableCall).getExpr().(VariableAccess).getLocation().isBefore(target_1.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getExpr().(VariableAccess).getLocation()))
}

predicate func_2(Parameter vsslc_179, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="CAfile"
		and target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsslc_179
		and target_2.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
}

predicate func_3(Parameter vsslc_179, Variable vCurl_cfree, ExprStmt target_3) {
		target_3.getExpr().(VariableCall).getExpr().(VariableAccess).getTarget()=vCurl_cfree
		and target_3.getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="clientcert"
		and target_3.getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsslc_179
}

predicate func_4(Parameter vsslc_179, Variable vCurl_cfree, ExprStmt target_4) {
		target_4.getExpr().(VariableCall).getExpr().(VariableAccess).getTarget()=vCurl_cfree
		and target_4.getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="CAfile"
		and target_4.getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsslc_179
}

predicate func_5(Parameter vsslc_179, ExprStmt target_5) {
		target_5.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="ca_info_blob"
		and target_5.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsslc_179
		and target_5.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
}

predicate func_6(Parameter vsslc_179, Variable vCurl_cfree, ExprStmt target_6) {
		target_6.getExpr().(VariableCall).getExpr().(VariableAccess).getTarget()=vCurl_cfree
		and target_6.getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="curves"
		and target_6.getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsslc_179
}

predicate func_7(Parameter vsslc_179, Variable vCurl_cfree, ExprStmt target_7) {
		target_7.getExpr().(VariableCall).getExpr().(VariableAccess).getTarget()=vCurl_cfree
		and target_7.getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="ca_info_blob"
		and target_7.getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsslc_179
}

from Function func, Parameter vsslc_179, Variable vCurl_cfree, ExprStmt target_2, ExprStmt target_3, ExprStmt target_4, ExprStmt target_5, ExprStmt target_6, ExprStmt target_7
where
not func_0(vsslc_179, vCurl_cfree, target_2, target_3, target_4, func)
and not func_1(vsslc_179, vCurl_cfree, target_5, target_6, target_7, func)
and func_2(vsslc_179, target_2)
and func_3(vsslc_179, vCurl_cfree, target_3)
and func_4(vsslc_179, vCurl_cfree, target_4)
and func_5(vsslc_179, target_5)
and func_6(vsslc_179, vCurl_cfree, target_6)
and func_7(vsslc_179, vCurl_cfree, target_7)
and vsslc_179.getType().hasName("ssl_primary_config *")
and vCurl_cfree.getType().hasName("curl_free_callback")
and vsslc_179.getFunction() = func
and not vCurl_cfree.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
