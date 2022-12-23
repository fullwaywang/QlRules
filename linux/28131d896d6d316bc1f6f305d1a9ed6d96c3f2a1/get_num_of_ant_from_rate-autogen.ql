/**
 * @name linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-get_num_of_ant_from_rate
 * @id cpp/linux/28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1/get-num-of-ant-from-rate
 * @description linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-get_num_of_ant_from_rate CVE-2020-24588
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vrate_n_flags_654) {
	exists(AddExpr target_0 |
		target_0.getAnOperand().(NotExpr).getOperand().(NotExpr).getOperand().(BitwiseAndExpr).getLeftOperand().(VariableAccess).getTarget()=vrate_n_flags_654
		and target_0.getAnOperand().(NotExpr).getOperand().(NotExpr).getOperand().(BitwiseAndExpr).getRightOperand().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1"
		and target_0.getAnOperand().(NotExpr).getOperand().(NotExpr).getOperand().(BitwiseAndExpr).getRightOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="14"
		and target_0.getAnOperand().(NotExpr).getOperand().(NotExpr).getOperand().(BitwiseAndExpr).getLeftOperand().(VariableAccess).getTarget()=vrate_n_flags_654
		and target_0.getAnOperand().(NotExpr).getOperand().(NotExpr).getOperand().(BitwiseAndExpr).getRightOperand().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="2"
		and target_0.getAnOperand().(NotExpr).getOperand().(NotExpr).getOperand().(BitwiseAndExpr).getRightOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="14")
}

predicate func_1(Parameter vrate_n_flags_654) {
	exists(AddExpr target_1 |
		target_1.getAnOperand() instanceof AddExpr
		and target_1.getAnOperand().(NotExpr).getOperand().(NotExpr).getOperand().(BitwiseAndExpr).getLeftOperand().(VariableAccess).getTarget()=vrate_n_flags_654
		and target_1.getAnOperand().(NotExpr).getOperand().(NotExpr).getOperand().(BitwiseAndExpr).getRightOperand().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="4"
		and target_1.getAnOperand().(NotExpr).getOperand().(NotExpr).getOperand().(BitwiseAndExpr).getRightOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="14")
}

from Function func, Parameter vrate_n_flags_654
where
func_0(vrate_n_flags_654)
and func_1(vrate_n_flags_654)
and vrate_n_flags_654.getType().hasName("u32")
and vrate_n_flags_654.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
