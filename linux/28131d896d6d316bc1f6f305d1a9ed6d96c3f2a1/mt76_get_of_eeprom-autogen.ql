/**
 * @name linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-mt76_get_of_eeprom
 * @id cpp/linux/28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1/mt76-get-of-eeprom
 * @description linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-mt76_get_of_eeprom CVE-2020-24588
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vdev_12, Variable vpart_19, Variable vret_23) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(0).(DoStmt).getCondition() instanceof Literal
		and target_0.getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand() instanceof Literal
		and target_0.getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand() instanceof Literal
		and target_0.getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(DeclStmt).getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(ClassAggregateLiteral).getValue()="{...}"
		and target_0.getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(DeclStmt).getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("const pi_entry")
		and target_0.getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("_dev_err")
		and target_0.getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="dev"
		and target_0.getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdev_12
		and target_0.getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="reading EEPROM from mtd %s failed: %i\n"
		and target_0.getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vpart_19
		and target_0.getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vret_23
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(VariableAccess).getTarget()=vret_23)
}

predicate func_6(Variable vret_23) {
	exists(GotoStmt target_6 |
		target_6.toString() = "goto ..."
		and target_6.getParent().(IfStmt).getCondition().(VariableAccess).getTarget()=vret_23)
}

predicate func_7(Parameter vdev_12) {
	exists(PointerFieldAccess target_7 |
		target_7.getTarget().getName()="dev"
		and target_7.getQualifier().(VariableAccess).getTarget()=vdev_12)
}

predicate func_8(Variable vpart_19) {
	exists(FunctionCall target_8 |
		target_8.getTarget().hasName("get_mtd_device_nm")
		and target_8.getArgument(0).(VariableAccess).getTarget()=vpart_19)
}

predicate func_9(Variable vret_23, Function func) {
	exists(IfStmt target_9 |
		target_9.getCondition().(VariableAccess).getTarget()=vret_23
		and target_9.getThen() instanceof GotoStmt
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_9)
}

from Function func, Parameter vdev_12, Variable vpart_19, Variable vret_23
where
not func_0(vdev_12, vpart_19, vret_23)
and func_6(vret_23)
and vdev_12.getType().hasName("mt76_dev *")
and func_7(vdev_12)
and vpart_19.getType().hasName("const char *")
and func_8(vpart_19)
and vret_23.getType().hasName("int")
and func_9(vret_23, func)
and vdev_12.getParentScope+() = func
and vpart_19.getParentScope+() = func
and vret_23.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
