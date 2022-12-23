/**
 * @name linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-rtw8852a_ctrl_ch
 * @id cpp/linux/28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1/rtw8852a-ctrl-ch
 * @description linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-rtw8852a_ctrl_ch CVE-2020-24588
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vrtwdev_709, Parameter vphy_idx_710) {
	exists(Literal target_0 |
		target_0.getValue()="1"
		and not target_0.getValue()="0"
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("rtw89_phy_write32_idx")
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vrtwdev_709
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="18200"
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(AddExpr).getValue()="3221225472"
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(AddExpr).getAnOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(AddExpr).getAnOperand().(SizeofTypeOperator).getValue()="0"
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(AddExpr).getAnOperand().(BitwiseAndExpr).getValue()="3221225472"
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(AddExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(AddExpr).getAnOperand().(SubExpr).getLeftOperand().(ComplementExpr).getOperand().(Literal).getValue()="0"
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(AddExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(AddExpr).getAnOperand().(SubExpr).getRightOperand().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1"
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(AddExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(AddExpr).getAnOperand().(SubExpr).getRightOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="30"
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(AddExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(AddExpr).getAnOperand().(Literal).getValue()="1"
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(AddExpr).getAnOperand().(BitwiseAndExpr).getRightOperand().(BinaryBitwiseOperation).getLeftOperand().(ComplementExpr).getOperand().(Literal).getValue()="0"
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(AddExpr).getAnOperand().(BitwiseAndExpr).getRightOperand().(BinaryBitwiseOperation).getRightOperand().(SubExpr).getLeftOperand().(SubExpr).getLeftOperand().(Literal).getValue()="64"
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(AddExpr).getAnOperand().(BitwiseAndExpr).getRightOperand().(BinaryBitwiseOperation).getRightOperand().(SubExpr).getLeftOperand().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(AddExpr).getAnOperand().(BitwiseAndExpr).getRightOperand().(BinaryBitwiseOperation).getRightOperand().(SubExpr).getRightOperand().(Literal).getValue()="31"
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vphy_idx_710)
}

from Function func, Parameter vrtwdev_709, Parameter vphy_idx_710
where
func_0(vrtwdev_709, vphy_idx_710)
and vrtwdev_709.getType().hasName("rtw89_dev *")
and vphy_idx_710.getType().hasName("rtw89_phy_idx")
and vrtwdev_709.getParentScope+() = func
and vphy_idx_710.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
