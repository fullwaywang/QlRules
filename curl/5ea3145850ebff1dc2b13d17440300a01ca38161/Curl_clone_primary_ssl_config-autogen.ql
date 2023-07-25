/**
 * @name curl-5ea3145850ebff1dc2b13d17440300a01ca38161-Curl_clone_primary_ssl_config
 * @id cpp/curl/5ea3145850ebff1dc2b13d17440300a01ca38161/Curl-clone-primary-ssl-config
 * @description curl-5ea3145850ebff1dc2b13d17440300a01ca38161-lib/vtls/vtls.c-Curl_clone_primary_ssl_config CVE-2021-22924
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vsource_154, Parameter vdest_155, FunctionCall target_2, IfStmt target_3, AddressOfExpr target_4, ExprStmt target_5, Function func) {
	exists(DoStmt target_0 |
		target_0.getCondition().(Literal).getValue()="0"
		and target_0.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getTarget().hasName("blobdup")
		and target_0.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="issuercert_blob"
		and target_0.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdest_155
		and target_0.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="issuercert_blob"
		and target_0.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsource_154
		and target_0.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(8)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(8).getFollowingStmt()=target_0)
		and target_2.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_4.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_5.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vsource_154, Parameter vdest_155, ExprStmt target_6, ExprStmt target_7, Function func) {
	exists(DoStmt target_1 |
		target_1.getCondition().(Literal).getValue()="0"
		and target_1.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(PointerFieldAccess).getTarget().getName()="issuercert"
		and target_1.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsource_154
		and target_1.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="issuercert"
		and target_1.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(PointerFieldAccess).getTarget().getName()="issuercert"
		and target_1.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_1.getStmt().(BlockStmt).getStmt(0).(IfStmt).getElse().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="issuercert"
		and target_1.getStmt().(BlockStmt).getStmt(0).(IfStmt).getElse().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdest_155
		and target_1.getStmt().(BlockStmt).getStmt(0).(IfStmt).getElse().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(11)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(11).getFollowingStmt()=target_1)
		and target_6.getExpr().(AssignExpr).getRValue().(VariableCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_1.getStmt().(BlockStmt).getStmt(0).(IfStmt).getElse().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_7.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(Parameter vsource_154, Parameter vdest_155, FunctionCall target_2) {
		target_2.getTarget().hasName("blobdup")
		and target_2.getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="ca_info_blob"
		and target_2.getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdest_155
		and target_2.getArgument(1).(PointerFieldAccess).getTarget().getName()="ca_info_blob"
		and target_2.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsource_154
}

predicate func_3(Parameter vsource_154, Parameter vdest_155, IfStmt target_3) {
		target_3.getCondition().(PointerFieldAccess).getTarget().getName()="CApath"
		and target_3.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsource_154
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="CApath"
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdest_155
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="CApath"
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsource_154
		and target_3.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(PointerFieldAccess).getTarget().getName()="CApath"
		and target_3.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdest_155
		and target_3.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_3.getElse().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="CApath"
		and target_3.getElse().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdest_155
		and target_3.getElse().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
}

predicate func_4(Parameter vdest_155, AddressOfExpr target_4) {
		target_4.getOperand().(PointerFieldAccess).getTarget().getName()="ca_info_blob"
		and target_4.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdest_155
}

predicate func_5(Parameter vsource_154, Parameter vdest_155, ExprStmt target_5) {
		target_5.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="CApath"
		and target_5.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdest_155
		and target_5.getExpr().(AssignExpr).getRValue().(VariableCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="CApath"
		and target_5.getExpr().(AssignExpr).getRValue().(VariableCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsource_154
}

predicate func_6(Parameter vsource_154, Parameter vdest_155, ExprStmt target_6) {
		target_6.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="CAfile"
		and target_6.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdest_155
		and target_6.getExpr().(AssignExpr).getRValue().(VariableCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="CAfile"
		and target_6.getExpr().(AssignExpr).getRValue().(VariableCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsource_154
}

predicate func_7(Parameter vsource_154, Parameter vdest_155, ExprStmt target_7) {
		target_7.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="clientcert"
		and target_7.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdest_155
		and target_7.getExpr().(AssignExpr).getRValue().(VariableCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="clientcert"
		and target_7.getExpr().(AssignExpr).getRValue().(VariableCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsource_154
}

from Function func, Parameter vsource_154, Parameter vdest_155, FunctionCall target_2, IfStmt target_3, AddressOfExpr target_4, ExprStmt target_5, ExprStmt target_6, ExprStmt target_7
where
not func_0(vsource_154, vdest_155, target_2, target_3, target_4, target_5, func)
and not func_1(vsource_154, vdest_155, target_6, target_7, func)
and func_2(vsource_154, vdest_155, target_2)
and func_3(vsource_154, vdest_155, target_3)
and func_4(vdest_155, target_4)
and func_5(vsource_154, vdest_155, target_5)
and func_6(vsource_154, vdest_155, target_6)
and func_7(vsource_154, vdest_155, target_7)
and vsource_154.getType().hasName("ssl_primary_config *")
and vdest_155.getType().hasName("ssl_primary_config *")
and vsource_154.getParentScope+() = func
and vdest_155.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
