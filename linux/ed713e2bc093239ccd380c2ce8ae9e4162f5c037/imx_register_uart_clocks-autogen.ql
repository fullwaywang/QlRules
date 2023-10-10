/**
 * @name linux-ed713e2bc093239ccd380c2ce8ae9e4162f5c037-imx_register_uart_clocks
 * @id cpp/linux/ed713e2bc093239ccd380c2ce8ae9e4162f5c037/imx_register_uart_clocks
 * @description linux-ed713e2bc093239ccd380c2ce8ae9e4162f5c037-imx_register_uart_clocks 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable vimx_keep_uart_clocks, Variable vimx_uart_clocks) {
	exists(IfStmt target_0 |
		target_0.getCondition().(NotExpr).getOperand().(VariableAccess).getTarget()=vimx_uart_clocks
		and target_0.getThen().(ReturnStmt).toString() = "return ..."
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(VariableAccess).getTarget()=vimx_keep_uart_clocks)
}

predicate func_1(Parameter vclk_count_169, Variable vimx_uart_clocks) {
	exists(AssignExpr target_1 |
		target_1.getLValue().(VariableAccess).getTarget()=vimx_uart_clocks
		and target_1.getRValue().(FunctionCall).getTarget().hasName("kcalloc")
		and target_1.getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vclk_count_169
		and target_1.getRValue().(FunctionCall).getArgument(1).(SizeofTypeOperator).getType() instanceof LongType
		and target_1.getRValue().(FunctionCall).getArgument(1).(SizeofTypeOperator).getValue()="8"
		and target_1.getRValue().(FunctionCall).getArgument(2).(BitwiseOrExpr).getValue()="3264"
		and target_1.getRValue().(FunctionCall).getArgument(2).(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getValue()="3136"
		and target_1.getRValue().(FunctionCall).getArgument(2).(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getLeftOperand().(Literal).getValue()="1024"
		and target_1.getRValue().(FunctionCall).getArgument(2).(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getRightOperand().(Literal).getValue()="2048"
		and target_1.getRValue().(FunctionCall).getArgument(2).(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getRightOperand().(Literal).getValue()="64"
		and target_1.getRValue().(FunctionCall).getArgument(2).(BitwiseOrExpr).getRightOperand().(Literal).getValue()="128")
}

from Function func, Parameter vclk_count_169, Variable vimx_keep_uart_clocks, Variable vimx_uart_clocks
where
not func_0(vimx_keep_uart_clocks, vimx_uart_clocks)
and vimx_keep_uart_clocks.getType().hasName("bool")
and vimx_uart_clocks.getType().hasName("clk **")
and func_1(vclk_count_169, vimx_uart_clocks)
and vclk_count_169.getParentScope+() = func
and not vimx_keep_uart_clocks.getParentScope+() = func
and not vimx_uart_clocks.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
