/**
 * @name openssl-3c66a669dfc7b3792f7af0758ea26fe8502ce70c-ssl3_get_key_exchange
 * @id cpp/openssl/3c66a669dfc7b3792f7af0758ea26fe8502ce70c/ssl3-get-key-exchange
 * @description openssl-3c66a669dfc7b3792f7af0758ea26fe8502ce70c-ssl3_get_key_exchange CVE-2015-3196
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vtmp_id_hint_1459) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("BUF_strdup")
		and not target_0.getTarget().hasName("BUF_strndup")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vtmp_id_hint_1459)
}

predicate func_3(Parameter vs_1359) {
	exists(PointerFieldAccess target_3 |
		target_3.getTarget().getName()="ctx"
		and target_3.getQualifier().(VariableAccess).getTarget()=vs_1359)
}

predicate func_7(Function func) {
	exists(Literal target_7 |
		target_7.getValue()="0"
		and target_7.getEnclosingFunction() = func)
}

predicate func_10(Variable valg_k_1367) {
	exists(DeclStmt target_10 |
		target_10.getDeclarationEntry(0).(VariableDeclarationEntry).getType() instanceof ArrayType
		and target_10.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(BitwiseAndExpr).getLeftOperand().(VariableAccess).getTarget()=valg_k_1367
		and target_10.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="256")
}

predicate func_11(Variable vp_1365, Variable vi_1367, Variable vtmp_id_hint_1459) {
	exists(FunctionCall target_11 |
		target_11.getTarget().hasName("memcpy")
		and target_11.getArgument(0).(VariableAccess).getTarget()=vtmp_id_hint_1459
		and target_11.getArgument(1).(VariableAccess).getTarget()=vp_1365
		and target_11.getArgument(2).(VariableAccess).getTarget()=vi_1367)
}

predicate func_12(Variable vi_1367, Variable valg_k_1367, Variable vtmp_id_hint_1459) {
	exists(ExprStmt target_12 |
		target_12.getExpr().(FunctionCall).getTarget().hasName("memset")
		and target_12.getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vtmp_id_hint_1459
		and target_12.getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vi_1367
		and target_12.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_12.getExpr().(FunctionCall).getArgument(2).(SubExpr).getLeftOperand().(AddExpr).getValue()="129"
		and target_12.getExpr().(FunctionCall).getArgument(2).(SubExpr).getRightOperand().(VariableAccess).getTarget()=vi_1367
		and target_12.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(BitwiseAndExpr).getLeftOperand().(VariableAccess).getTarget()=valg_k_1367
		and target_12.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="256")
}

predicate func_15(Variable valg_k_1367, Parameter vs_1359) {
	exists(ExprStmt target_15 |
		target_15.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="psk_identity_hint"
		and target_15.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="ctx"
		and target_15.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1359
		and target_15.getExpr().(AssignExpr).getRValue() instanceof FunctionCall
		and target_15.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(BitwiseAndExpr).getLeftOperand().(VariableAccess).getTarget()=valg_k_1367
		and target_15.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="256")
}

predicate func_17(Variable val_1366, Variable valg_k_1367, Parameter vs_1359) {
	exists(IfStmt target_17 |
		target_17.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="psk_identity_hint"
		and target_17.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="ctx"
		and target_17.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1359
		and target_17.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_17.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=val_1366
		and target_17.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="40"
		and target_17.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ERR_put_error")
		and target_17.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0) instanceof Literal
		and target_17.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof Literal
		and target_17.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(BitwiseOrExpr).getValue()="65"
		and target_17.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(3) instanceof StringLiteral
		and target_17.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(4) instanceof Literal
		and target_17.getThen().(BlockStmt).getStmt(2).(GotoStmt).toString() = "goto ..."
		and target_17.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(BitwiseAndExpr).getLeftOperand().(VariableAccess).getTarget()=valg_k_1367
		and target_17.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="256")
}

from Function func, Variable vp_1365, Variable val_1366, Variable vi_1367, Variable valg_k_1367, Variable vtmp_id_hint_1459, Parameter vs_1359
where
func_0(vtmp_id_hint_1459)
and func_3(vs_1359)
and func_7(func)
and func_10(valg_k_1367)
and func_11(vp_1365, vi_1367, vtmp_id_hint_1459)
and func_12(vi_1367, valg_k_1367, vtmp_id_hint_1459)
and func_15(valg_k_1367, vs_1359)
and func_17(val_1366, valg_k_1367, vs_1359)
and vp_1365.getType().hasName("unsigned char *")
and val_1366.getType().hasName("int")
and vi_1367.getType().hasName("long")
and valg_k_1367.getType().hasName("long")
and vtmp_id_hint_1459.getType().hasName("char[129]")
and vs_1359.getType().hasName("SSL *")
and vp_1365.getParentScope+() = func
and val_1366.getParentScope+() = func
and vi_1367.getParentScope+() = func
and valg_k_1367.getParentScope+() = func
and vtmp_id_hint_1459.getParentScope+() = func
and vs_1359.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
