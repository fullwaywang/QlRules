import cpp

predicate func_0(Parameter vsource, Parameter vdest, Function func) {
	exists(DoStmt target_0 |
		target_0.getCondition().(Literal).getValue()="0"
		and target_0.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getTarget().hasName("blobdup")
		and target_0.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getType().hasName("CURLcode")
		and target_0.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="issuercert_blob"
		and target_0.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdest
		and target_0.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="issuercert_blob"
		and target_0.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsource
		and target_0.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_0)
}

predicate func_1(Parameter vsource, Parameter vdest, Variable vCurl_cstrdup, Function func) {
	exists(DoStmt target_1 |
		target_1.getCondition().(Literal).getValue()="0"
		and target_1.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(PointerFieldAccess).getTarget().getName()="issuercert"
		and target_1.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(PointerFieldAccess).getType().hasName("char *")
		and target_1.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsource
		and target_1.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="issuercert"
		and target_1.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdest
		and target_1.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableCall).getExpr().(VariableAccess).getTarget()=vCurl_cstrdup
		and target_1.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="issuercert"
		and target_1.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsource
		and target_1.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(PointerFieldAccess).getTarget().getName()="issuercert"
		and target_1.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdest
		and target_1.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_1.getStmt().(BlockStmt).getStmt(0).(IfStmt).getElse().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="issuercert"
		and target_1.getStmt().(BlockStmt).getStmt(0).(IfStmt).getElse().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdest
		and target_1.getStmt().(BlockStmt).getStmt(0).(IfStmt).getElse().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_1)
}

from Function func, Parameter vsource, Parameter vdest, Variable vCurl_cstrdup
where
not func_0(vsource, vdest, func)
and not func_1(vsource, vdest, vCurl_cstrdup, func)
and vsource.getType().hasName("ssl_primary_config *")
and vdest.getType().hasName("ssl_primary_config *")
and vCurl_cstrdup.getType().hasName("curl_strdup_callback")
and vsource.getParentScope+() = func
and vdest.getParentScope+() = func
and not vCurl_cstrdup.getParentScope+() = func
select func, vsource, vdest, vCurl_cstrdup
