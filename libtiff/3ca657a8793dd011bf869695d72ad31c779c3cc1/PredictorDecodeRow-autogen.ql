/**
 * @name libtiff-3ca657a8793dd011bf869695d72ad31c779c3cc1-PredictorDecodeRow
 * @id cpp/libtiff/3ca657a8793dd011bf869695d72ad31c779c3cc1/PredictorDecodeRow
 * @description libtiff-3ca657a8793dd011bf869695d72ad31c779c3cc1-libtiff/tif_predict.c-PredictorDecodeRow CVE-2016-9535
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vop0_426, Parameter vocc0_426, Variable vsp_428, Parameter vtif_426, ExprCall target_0) {
		target_0.getExpr().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getTarget().getName()="decodepfunc"
		and target_0.getExpr().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsp_428
		and target_0.getArgument(0).(VariableAccess).getTarget()=vtif_426
		and target_0.getArgument(1).(VariableAccess).getTarget()=vop0_426
		and target_0.getArgument(2).(VariableAccess).getTarget()=vocc0_426
}

predicate func_1(ExprCall target_3, Function func, ExprStmt target_1) {
		target_1.getExpr() instanceof ExprCall
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_3
		and target_1.getEnclosingFunction() = func
}

predicate func_3(Parameter vop0_426, Parameter vocc0_426, Variable vsp_428, Parameter vtif_426, ExprCall target_3) {
		target_3.getExpr().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getTarget().getName()="decoderow"
		and target_3.getExpr().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsp_428
		and target_3.getArgument(0).(VariableAccess).getTarget()=vtif_426
		and target_3.getArgument(1).(VariableAccess).getTarget()=vop0_426
		and target_3.getArgument(2).(VariableAccess).getTarget()=vocc0_426
		and target_3.getArgument(3).(VariableAccess).getTarget().getType().hasName("uint16")
}

from Function func, Parameter vop0_426, Parameter vocc0_426, Variable vsp_428, Parameter vtif_426, ExprCall target_0, ExprStmt target_1, ExprCall target_3
where
func_0(vop0_426, vocc0_426, vsp_428, vtif_426, target_0)
and func_1(target_3, func, target_1)
and func_3(vop0_426, vocc0_426, vsp_428, vtif_426, target_3)
and vop0_426.getType().hasName("uint8 *")
and vocc0_426.getType().hasName("tmsize_t")
and vsp_428.getType().hasName("TIFFPredictorState *")
and vtif_426.getType().hasName("TIFF *")
and vop0_426.getFunction() = func
and vocc0_426.getFunction() = func
and vsp_428.(LocalVariable).getFunction() = func
and vtif_426.getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
