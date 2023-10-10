/**
 * @name linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-mt7615_mcu_init
 * @id cpp/linux/28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1/mt7615-mcu-init
 * @description linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-mt7615_mcu_init CVE-2020-24588
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vret_1884, Parameter vdev_1876, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(PointerFieldAccess).getTarget().getName()="dbdc_support"
		and target_0.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdev_1876
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vret_1884
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("mt7615_mcu_cal_cache_apply")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdev_1876
		and target_0.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(VariableAccess).getTarget()=vret_1884
		and target_0.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(ReturnStmt).getExpr().(VariableAccess).getTarget()=vret_1884
		and (func.getEntryPoint().(BlockStmt).getStmt(10)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(10).getFollowingStmt()=target_0))
}

predicate func_3(Parameter vdev_1876) {
	exists(FunctionCall target_3 |
		target_3.getTarget().hasName("mt7615_mcu_fw_log_2_host")
		and target_3.getArgument(0).(VariableAccess).getTarget()=vdev_1876
		and target_3.getArgument(1).(Literal).getValue()="0")
}

predicate func_4(Function func) {
	exists(Literal target_4 |
		target_4.getValue()="0"
		and target_4.getEnclosingFunction() = func)
}

predicate func_5(Variable vret_1884) {
	exists(ReturnStmt target_5 |
		target_5.getExpr().(VariableAccess).getTarget()=vret_1884
		and target_5.getParent().(IfStmt).getCondition().(VariableAccess).getTarget()=vret_1884)
}

predicate func_6(Parameter vdev_1876) {
	exists(PointerFieldAccess target_6 |
		target_6.getTarget().getName()="(unknown field)"
		and target_6.getQualifier().(VariableAccess).getTarget()=vdev_1876)
}

from Function func, Variable vret_1884, Parameter vdev_1876
where
not func_0(vret_1884, vdev_1876, func)
and func_3(vdev_1876)
and func_4(func)
and vret_1884.getType().hasName("int")
and func_5(vret_1884)
and vdev_1876.getType().hasName("mt7615_dev *")
and func_6(vdev_1876)
and vret_1884.getParentScope+() = func
and vdev_1876.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
