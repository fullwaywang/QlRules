/**
 * @name linux-579028dec182c026b9a85725682f1dfbdc825eaa-hci_dev_do_open
 * @id cpp/linux/579028dec182c026b9a85725682f1dfbdc825eaa/hci-dev-do-open
 * @description linux-579028dec182c026b9a85725682f1dfbdc825eaa-hci_dev_do_open CVE-2021-3564
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vhdev_1433) {
	exists(PointerFieldAccess target_0 |
		target_0.getTarget().getName()="cmd_work"
		and target_0.getQualifier().(VariableAccess).getTarget()=vhdev_1433)
}

predicate func_1(Parameter vhdev_1433) {
	exists(PointerFieldAccess target_1 |
		target_1.getTarget().getName()="rx_work"
		and target_1.getQualifier().(VariableAccess).getTarget()=vhdev_1433)
}

from Function func, Parameter vhdev_1433
where
func_0(vhdev_1433)
and func_1(vhdev_1433)
and vhdev_1433.getType().hasName("hci_dev *")
and vhdev_1433.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
