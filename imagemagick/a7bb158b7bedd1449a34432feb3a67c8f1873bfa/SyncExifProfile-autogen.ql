/**
 * @name imagemagick-a7bb158b7bedd1449a34432feb3a67c8f1873bfa-SyncExifProfile
 * @id cpp/imagemagick/a7bb158b7bedd1449a34432feb3a67c8f1873bfa/SyncExifProfile
 * @description imagemagick-a7bb158b7bedd1449a34432feb3a67c8f1873bfa-MagickCore/profile.c-SyncExifProfile CVE-2016-7799
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vformat_2027, BreakStmt target_2, ExprStmt target_3, RelationalOperation target_1) {
	exists(LogicalOrExpr target_0 |
		target_0.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vformat_2027
		and target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_0.getAnOperand() instanceof RelationalOperation
		and target_0.getParent().(IfStmt).getThen()=target_2
		and target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation())
		and target_0.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation().isBefore(target_1.getGreaterOperand().(SubExpr).getLeftOperand().(VariableAccess).getLocation()))
}

predicate func_1(Variable vformat_2027, BreakStmt target_2, RelationalOperation target_1) {
		 (target_1 instanceof GEExpr or target_1 instanceof LEExpr)
		and target_1.getGreaterOperand().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vformat_2027
		and target_1.getGreaterOperand().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_1.getLesserOperand().(Literal).getValue()="12"
		and target_1.getParent().(IfStmt).getThen()=target_2
}

predicate func_2(BreakStmt target_2) {
		target_2.toString() = "break;"
}

predicate func_3(Variable vformat_2027, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vformat_2027
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ReadProfileShort")
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(Literal).getValue()="2"
}

from Function func, Variable vformat_2027, RelationalOperation target_1, BreakStmt target_2, ExprStmt target_3
where
not func_0(vformat_2027, target_2, target_3, target_1)
and func_1(vformat_2027, target_2, target_1)
and func_2(target_2)
and func_3(vformat_2027, target_3)
and vformat_2027.getType().hasName("ssize_t")
and vformat_2027.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
