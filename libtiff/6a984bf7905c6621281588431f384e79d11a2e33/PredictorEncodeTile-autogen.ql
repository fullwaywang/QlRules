/**
 * @name libtiff-6a984bf7905c6621281588431f384e79d11a2e33-PredictorEncodeTile
 * @id cpp/libtiff/6a984bf7905c6621281588431f384e79d11a2e33/PredictorEncodeTile
 * @description libtiff-6a984bf7905c6621281588431f384e79d11a2e33-libtiff/tif_predict.c-PredictorEncodeTile CVE-2016-9535
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vworking_copy_695, EqualityOperation target_1, ExprStmt target_2, ExprStmt target_3) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("_TIFFfree")
		and target_0.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vworking_copy_695
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_1
		and target_2.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation().isBefore(target_0.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_0.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_3.getExpr().(AssignExpr).getRValue().(ExprCall).getArgument(1).(VariableAccess).getLocation()))
}

predicate func_1(EqualityOperation target_1) {
		target_1.getAnOperand().(RemExpr).getLeftOperand().(VariableAccess).getTarget().getType().hasName("tmsize_t")
		and target_1.getAnOperand().(RemExpr).getRightOperand().(VariableAccess).getTarget().getType().hasName("tmsize_t")
		and target_1.getAnOperand().(Literal).getValue()="0"
}

predicate func_2(Variable vworking_copy_695, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("unsigned char *")
		and target_2.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vworking_copy_695
}

predicate func_3(Variable vworking_copy_695, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("int")
		and target_3.getExpr().(AssignExpr).getRValue().(ExprCall).getExpr().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getTarget().getName()="encodetile"
		and target_3.getExpr().(AssignExpr).getRValue().(ExprCall).getExpr().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("TIFFPredictorState *")
		and target_3.getExpr().(AssignExpr).getRValue().(ExprCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("TIFF *")
		and target_3.getExpr().(AssignExpr).getRValue().(ExprCall).getArgument(1).(VariableAccess).getTarget()=vworking_copy_695
		and target_3.getExpr().(AssignExpr).getRValue().(ExprCall).getArgument(2).(VariableAccess).getTarget().getType().hasName("tmsize_t")
		and target_3.getExpr().(AssignExpr).getRValue().(ExprCall).getArgument(3).(VariableAccess).getTarget().getType().hasName("uint16")
}

from Function func, Variable vworking_copy_695, EqualityOperation target_1, ExprStmt target_2, ExprStmt target_3
where
not func_0(vworking_copy_695, target_1, target_2, target_3)
and func_1(target_1)
and func_2(vworking_copy_695, target_2)
and func_3(vworking_copy_695, target_3)
and vworking_copy_695.getType().hasName("uint8 *")
and vworking_copy_695.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
