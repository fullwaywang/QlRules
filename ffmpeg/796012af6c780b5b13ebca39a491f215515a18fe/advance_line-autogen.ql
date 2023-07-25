/**
 * @name ffmpeg-796012af6c780b5b13ebca39a491f215515a18fe-advance_line
 * @id cpp/ffmpeg/796012af6c780b5b13ebca39a491f215515a18fe/advance-line
 * @description ffmpeg-796012af6c780b5b13ebca39a491f215515a18fe-libavcodec/targa.c-advance_line CVE-2013-0878
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vy_35, Parameter vh_35, ExprStmt target_2, PointerDereferenceExpr target_1, RelationalOperation target_3) {
	exists(LogicalAndExpr target_0 |
		target_0.getAnOperand() instanceof PointerDereferenceExpr
		and target_0.getAnOperand().(RelationalOperation).getLesserOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vy_35
		and target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vh_35
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0) instanceof ReturnStmt
		and target_2.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(RelationalOperation).getLesserOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation())
		and target_0.getAnOperand().(RelationalOperation).getLesserOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation().isBefore(target_1.getOperand().(VariableAccess).getLocation())
		and target_3.getGreaterOperand().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vy_35, PointerDereferenceExpr target_1) {
		target_1.getOperand().(VariableAccess).getTarget()=vy_35
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0) instanceof ReturnStmt
}

predicate func_2(Parameter vy_35, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vy_35
		and target_2.getExpr().(AssignExpr).getRValue().(BitwiseAndExpr).getLeftOperand().(AddExpr).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vy_35
		and target_2.getExpr().(AssignExpr).getRValue().(BitwiseAndExpr).getLeftOperand().(AddExpr).getAnOperand().(Literal).getValue()="1"
		and target_2.getExpr().(AssignExpr).getRValue().(BitwiseAndExpr).getRightOperand().(SubExpr).getLeftOperand().(VariableAccess).getTarget().getType().hasName("int")
		and target_2.getExpr().(AssignExpr).getRValue().(BitwiseAndExpr).getRightOperand().(SubExpr).getRightOperand().(Literal).getValue()="1"
}

predicate func_3(Parameter vy_35, Parameter vh_35, RelationalOperation target_3) {
		 (target_3 instanceof GTExpr or target_3 instanceof LTExpr)
		and target_3.getLesserOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vy_35
		and target_3.getGreaterOperand().(VariableAccess).getTarget()=vh_35
}

from Function func, Parameter vy_35, Parameter vh_35, PointerDereferenceExpr target_1, ExprStmt target_2, RelationalOperation target_3
where
not func_0(vy_35, vh_35, target_2, target_1, target_3)
and func_1(vy_35, target_1)
and func_2(vy_35, target_2)
and func_3(vy_35, vh_35, target_3)
and vy_35.getType().hasName("int *")
and vh_35.getType().hasName("int")
and vy_35.getFunction() = func
and vh_35.getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
