/**
 * @name openssh-486c4dc3b83b4b67d663fb0fa62bc24138ec3946-compat_pkalg_proposal
 * @id cpp/openssh/486c4dc3b83b4b67d663fb0fa62bc24138ec3946/compat-pkalg-proposal
 * @description openssh-486c4dc3b83b4b67d663fb0fa62bc24138ec3946-compat_pkalg_proposal CVE-2023-25136
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vpkalg_prop_174) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("xstrdup")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vpkalg_prop_174)
}

predicate func_1(Parameter vpkalg_prop_174, Parameter vssh_174) {
	exists(ReturnStmt target_1 |
		target_1.getExpr().(VariableAccess).getTarget()=vpkalg_prop_174
		and target_1.getParent().(IfStmt).getCondition().(NotExpr).getOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="compat"
		and target_1.getParent().(IfStmt).getCondition().(NotExpr).getOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vssh_174
		and target_1.getParent().(IfStmt).getCondition().(NotExpr).getOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="8192")
}

predicate func_2(Parameter vpkalg_prop_174) {
	exists(VariableAccess target_2 |
		target_2.getTarget()=vpkalg_prop_174)
}

from Function func, Parameter vpkalg_prop_174, Parameter vssh_174
where
not func_0(vpkalg_prop_174)
and func_1(vpkalg_prop_174, vssh_174)
and func_2(vpkalg_prop_174)
and vpkalg_prop_174.getType().hasName("char *")
and vssh_174.getType().hasName("ssh *")
and vpkalg_prop_174.getParentScope+() = func
and vssh_174.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
