/**
 * @name linux-ca7a03c4175366a92cee0ccc4fec0038c3266e26-fib6_rule_suppress
 * @id cpp/linux/ca7a03c4175366a92cee0ccc4fec0038c3266e26/fib6-rule-suppress
 * @description linux-ca7a03c4175366a92cee0ccc4fec0038c3266e26-fib6_rule_suppress 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter varg_263, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(NotExpr).getOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="flags"
		and target_0.getCondition().(NotExpr).getOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=varg_263
		and target_0.getCondition().(NotExpr).getOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="1"
		and target_0.getThen() instanceof ExprStmt
		and (func.getEntryPoint().(BlockStmt).getStmt(9)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(9).getFollowingStmt()=target_0))
}

predicate func_1(Variable vrt_266, Function func) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(FunctionCall).getTarget().hasName("ip6_rt_put")
		and target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vrt_266
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_1)
}

predicate func_2(Parameter varg_263) {
	exists(PointerFieldAccess target_2 |
		target_2.getTarget().getName()="result"
		and target_2.getQualifier().(VariableAccess).getTarget()=varg_263)
}

from Function func, Parameter varg_263, Variable vrt_266
where
not func_0(varg_263, func)
and func_1(vrt_266, func)
and varg_263.getType().hasName("fib_lookup_arg *")
and func_2(varg_263)
and vrt_266.getType().hasName("rt6_info *")
and varg_263.getParentScope+() = func
and vrt_266.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
