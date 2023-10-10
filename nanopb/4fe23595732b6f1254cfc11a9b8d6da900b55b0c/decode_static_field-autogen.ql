/**
 * @name nanopb-4fe23595732b6f1254cfc11a9b8d6da900b55b0c-decode_static_field
 * @id cpp/nanopb/4fe23595732b6f1254cfc11a9b8d6da900b55b0c/decode-static-field
 * @description nanopb-4fe23595732b6f1254cfc11a9b8d6da900b55b0c-pb_decode.c-decode_static_field CVE-2020-26243
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter viter_406, BlockStmt target_2, ExprStmt target_3, ExprStmt target_4) {
	exists(LogicalAndExpr target_0 |
		target_0.getAnOperand() instanceof EqualityOperation
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getTarget().getName()="pSize"
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=viter_406
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="tag"
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="pos"
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=viter_406
		and target_0.getParent().(IfStmt).getThen()=target_2
		and target_3.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_4.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Variable vtype_408, BlockStmt target_2, EqualityOperation target_1) {
		target_1.getAnOperand().(BitwiseAndExpr).getLeftOperand().(VariableAccess).getTarget()=vtype_408
		and target_1.getAnOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="15"
		and target_1.getAnOperand().(Literal).getValue()="8"
		and target_1.getParent().(IfStmt).getThen()=target_2
}

predicate func_2(Parameter viter_406, BlockStmt target_2) {
		target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("memset")
		and target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="pData"
		and target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=viter_406
		and target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="data_size"
		and target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="pos"
		and target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=viter_406
}

predicate func_3(Parameter viter_406, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getTarget().getName()="pSize"
		and target_3.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=viter_406
		and target_3.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="tag"
		and target_3.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="pos"
		and target_3.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=viter_406
}

predicate func_4(Parameter viter_406, ExprStmt target_4) {
		target_4.getExpr().(FunctionCall).getTarget().hasName("memset")
		and target_4.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="pData"
		and target_4.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=viter_406
		and target_4.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_4.getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="data_size"
		and target_4.getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="pos"
		and target_4.getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=viter_406
}

from Function func, Parameter viter_406, Variable vtype_408, EqualityOperation target_1, BlockStmt target_2, ExprStmt target_3, ExprStmt target_4
where
not func_0(viter_406, target_2, target_3, target_4)
and func_1(vtype_408, target_2, target_1)
and func_2(viter_406, target_2)
and func_3(viter_406, target_3)
and func_4(viter_406, target_4)
and viter_406.getType().hasName("pb_field_iter_t *")
and vtype_408.getType().hasName("pb_type_t")
and viter_406.getParentScope+() = func
and vtype_408.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
