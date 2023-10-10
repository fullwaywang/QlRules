/**
 * @name libtiff-3ca657a8793dd011bf869695d72ad31c779c3cc1-PredictorEncodeRow
 * @id cpp/libtiff/3ca657a8793dd011bf869695d72ad31c779c3cc1/PredictorEncodeRow
 * @description libtiff-3ca657a8793dd011bf869695d72ad31c779c3cc1-libtiff/tif_predict.c-PredictorEncodeRow CVE-2016-9535
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(NotExpr).getOperand() instanceof ExprCall
		and target_0.getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(4)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(4).getFollowingStmt()=target_0))
}

predicate func_1(Parameter vbp_619, Parameter vcc_619, Variable vsp_621, Parameter vtif_619, ExprCall target_1) {
		target_1.getExpr().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getTarget().getName()="encodepfunc"
		and target_1.getExpr().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsp_621
		and target_1.getArgument(0).(VariableAccess).getTarget()=vtif_619
		and target_1.getArgument(1).(VariableAccess).getTarget()=vbp_619
		and target_1.getArgument(2).(VariableAccess).getTarget()=vcc_619
}

predicate func_2(Function func, ExprStmt target_2) {
		target_2.getExpr() instanceof ExprCall
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_2
}

from Function func, Parameter vbp_619, Parameter vcc_619, Variable vsp_621, Parameter vtif_619, ExprCall target_1, ExprStmt target_2
where
not func_0(func)
and func_1(vbp_619, vcc_619, vsp_621, vtif_619, target_1)
and func_2(func, target_2)
and vbp_619.getType().hasName("uint8 *")
and vcc_619.getType().hasName("tmsize_t")
and vsp_621.getType().hasName("TIFFPredictorState *")
and vtif_619.getType().hasName("TIFF *")
and vbp_619.getFunction() = func
and vcc_619.getFunction() = func
and vsp_621.(LocalVariable).getFunction() = func
and vtif_619.getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
