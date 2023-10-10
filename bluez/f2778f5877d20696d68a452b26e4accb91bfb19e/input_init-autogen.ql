/**
 * @name bluez-f2778f5877d20696d68a452b26e4accb91bfb19e-input_init
 * @id cpp/bluez/f2778f5877d20696d68a452b26e4accb91bfb19e/input-init
 * @description bluez-f2778f5877d20696d68a452b26e4accb91bfb19e-profiles/input/manager.c-input_init CVE-2020-0556
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_1(Variable vconfig_93, Variable verr_94, VariableAccess target_3, ExprStmt target_4, IfStmt target_5, AddressOfExpr target_6) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("gboolean")
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("g_key_file_get_boolean")
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vconfig_93
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(StringLiteral).getValue()="General"
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(StringLiteral).getValue()="LEAutoSecurity"
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=verr_94
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(8)=target_1
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_3
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_5.getCondition().(VariableAccess).getLocation())
		and target_6.getOperand().(VariableAccess).getLocation().isBefore(target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(AddressOfExpr).getOperand().(VariableAccess).getLocation()))
}

predicate func_2(Variable verr_94, VariableAccess target_3) {
	exists(IfStmt target_2 |
		target_2.getCondition().(NotExpr).getOperand().(VariableAccess).getTarget()=verr_94
		and target_2.getThen().(BlockStmt).getStmt(0).(DoStmt).getCondition() instanceof Literal
		and target_2.getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(BitwiseAndExpr).getLeftOperand().(ValueFieldAccess).getTarget().getName()="flags"
		and target_2.getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("btd_debug")
		and target_2.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("input_set_auto_sec")
		and target_2.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getType().hasName("gboolean")
		and target_2.getElse().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("g_clear_error")
		and target_2.getElse().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=verr_94
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(9)=target_2
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_3)
}

predicate func_3(Variable vconfig_93, VariableAccess target_3) {
		target_3.getTarget()=vconfig_93
}

predicate func_4(Variable vconfig_93, Variable verr_94, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("g_key_file_get_boolean")
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vconfig_93
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(StringLiteral).getValue()="General"
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(StringLiteral).getValue()="ClassicBondedOnly"
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=verr_94
}

predicate func_5(Variable vconfig_93, IfStmt target_5) {
		target_5.getCondition().(VariableAccess).getTarget()=vconfig_93
		and target_5.getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("g_key_file_free")
		and target_5.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vconfig_93
}

predicate func_6(Variable verr_94, AddressOfExpr target_6) {
		target_6.getOperand().(VariableAccess).getTarget()=verr_94
}

from Function func, Variable vconfig_93, Variable verr_94, VariableAccess target_3, ExprStmt target_4, IfStmt target_5, AddressOfExpr target_6
where
not func_1(vconfig_93, verr_94, target_3, target_4, target_5, target_6)
and not func_2(verr_94, target_3)
and func_3(vconfig_93, target_3)
and func_4(vconfig_93, verr_94, target_4)
and func_5(vconfig_93, target_5)
and func_6(verr_94, target_6)
and vconfig_93.getType().hasName("GKeyFile *")
and verr_94.getType().hasName("GError *")
and vconfig_93.getParentScope+() = func
and verr_94.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
