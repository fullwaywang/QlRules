/**
 * @name linux-5e7a2c6494813e58252caf342f5ddb166ad44d1a-mt7663s_mcu_init
 * @id cpp/linux/5e7a2c6494813e58252caf342f5ddb166ad44d1a/mt7663s-mcu-init
 * @description linux-5e7a2c6494813e58252caf342f5ddb166ad44d1a-mt7663s_mcu_init CVE-2020-24588
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vdev_112) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("mt7663s_mcu_drv_pmctrl")
		and not target_0.getTarget().hasName("__mt7663s_mcu_drv_pmctrl")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vdev_112)
}

from Function func, Parameter vdev_112
where
func_0(vdev_112)
and vdev_112.getType().hasName("mt7615_dev *")
and vdev_112.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
