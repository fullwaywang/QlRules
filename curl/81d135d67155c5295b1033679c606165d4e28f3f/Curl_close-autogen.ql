import cpp

predicate func_0(Parameter vdata) {
	exists(BlockStmt target_0 |
		target_0.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("curl_multi_cleanup")
		and target_0.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getType().hasName("CURLMcode")
		and target_0.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="multi_easy"
		and target_0.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getType().hasName("Curl_multi *")
		and target_0.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata
		and target_0.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getType().hasName("Curl_multi *")
		and target_0.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="multi_easy"
		and target_0.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getType().hasName("Curl_multi *")
		and target_0.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata
		and target_0.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_0.getParent().(IfStmt).getCondition().(PointerFieldAccess).getTarget().getName()="multi_easy"
		and target_0.getParent().(IfStmt).getCondition().(PointerFieldAccess).getType().hasName("Curl_multi *")
		and target_0.getParent().(IfStmt).getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata)
}

predicate func_1(Parameter vdata) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(FunctionCall).getTarget().hasName("curl_multi_cleanup")
		and target_1.getExpr().(FunctionCall).getType().hasName("CURLMcode")
		and target_1.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="multi_easy"
		and target_1.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getType().hasName("Curl_multi *")
		and target_1.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata
		and target_1.getParent().(IfStmt).getCondition().(PointerFieldAccess).getTarget().getName()="multi_easy"
		and target_1.getParent().(IfStmt).getCondition().(PointerFieldAccess).getType().hasName("Curl_multi *")
		and target_1.getParent().(IfStmt).getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata)
}

from Function func, Parameter vdata
where
not func_0(vdata)
and func_1(vdata)
and vdata.getType().hasName("Curl_easy *")
and vdata.getParentScope+() = func
select func, vdata
