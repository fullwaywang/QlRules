/**
 * @name linux-5e7a2c6494813e58252caf342f5ddb166ad44d1a-mt7615_init_device
 * @id cpp/linux/5e7a2c6494813e58252caf342f5ddb166ad44d1a/mt7615-init-device
 * @description linux-5e7a2c6494813e58252caf342f5ddb166ad44d1a-mt7615_init_device CVE-2020-24588
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vdev_498) {
	exists(ValueFieldAccess target_0 |
		target_0.getTarget().getName()="mphy"
		and target_0.getQualifier().(PointerFieldAccess).getTarget().getName()="(unknown field)"
		and target_0.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdev_498)
}

predicate func_1(Function func) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(FunctionCall).getTarget().hasName("set_bit")
		and target_1.getExpr().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(ValueFieldAccess).getTarget().getName()="state"
		and target_1.getExpr().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier() instanceof ValueFieldAccess
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_1)
}

from Function func, Parameter vdev_498
where
func_0(vdev_498)
and func_1(func)
and vdev_498.getType().hasName("mt7615_dev *")
and vdev_498.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
