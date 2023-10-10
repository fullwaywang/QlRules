/**
 * @name linux-6dee930f6f6776d1e5a7edf542c6863b47d9f078-free_charger_irq
 * @id cpp/linux/6dee930f6f6776d1e5a7edf542c6863b47d9f078/free_charger_irq
 * @description linux-6dee930f6f6776d1e5a7edf542c6863b47d9f078-free_charger_irq 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Parameter vwm8350_519, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("wm8350_free_irq")
		and target_0.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vwm8350_519
		and target_0.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="6"
		and target_0.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vwm8350_519
		and (func.getEntryPoint().(BlockStmt).getStmt(6)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(6).getFollowingStmt()=target_0))
}

predicate func_1(Parameter vwm8350_519) {
	exists(FunctionCall target_1 |
		target_1.getTarget().hasName("wm8350_free_irq")
		and target_1.getArgument(0).(VariableAccess).getTarget()=vwm8350_519
		and target_1.getArgument(1).(Literal).getValue()="5"
		and target_1.getArgument(2).(VariableAccess).getTarget()=vwm8350_519)
}

from Function func, Parameter vwm8350_519
where
not func_0(vwm8350_519, func)
and vwm8350_519.getType().hasName("wm8350 *")
and func_1(vwm8350_519)
and vwm8350_519.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
