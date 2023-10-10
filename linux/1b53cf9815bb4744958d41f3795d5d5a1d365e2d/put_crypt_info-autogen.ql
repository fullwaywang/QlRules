/**
 * @name linux-1b53cf9815bb4744958d41f3795d5d5a1d365e2d-put_crypt_info
 * @id cpp/linux/1b53cf9815bb4744958d41f3795d5d5a1d365e2d/put-crypt-info
 * @description linux-1b53cf9815bb4744958d41f3795d5d5a1d365e2d-put_crypt_info NULL
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vci_167, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("key_put")
		and target_0.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="ci_keyring_key"
		and target_0.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vci_167
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_0)
}

from Function func, Parameter vci_167
where
func_0(vci_167, func)
and vci_167.getType().hasName("fscrypt_info *")
and vci_167.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
