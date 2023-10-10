/**
 * @name linux-5e7a2c6494813e58252caf342f5ddb166ad44d1a-mt76x0e_register_device
 * @id cpp/linux/5e7a2c6494813e58252caf342f5ddb166ad44d1a/mt76x0e-register-device
 * @description linux-5e7a2c6494813e58252caf342f5ddb166ad44d1a-mt76x0e_register_device CVE-2020-24588
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_1(Parameter vdev_90) {
	exists(FunctionCall target_1 |
		target_1.getTarget().hasName("mt76x02_eeprom_get")
		and not target_1.getTarget().hasName("mt76x0e_init_hardware")
		and target_1.getArgument(0).(VariableAccess).getTarget()=vdev_90)
}

predicate func_2(Parameter vdev_90) {
	exists(PointerFieldAccess target_2 |
		target_2.getTarget().getName()="(unknown field)"
		and target_2.getQualifier().(VariableAccess).getTarget()=vdev_90)
}

predicate func_3(Parameter vdev_90) {
	exists(FunctionCall target_3 |
		target_3.getTarget().hasName("mt76x0_chip_onoff")
		and target_3.getArgument(0).(VariableAccess).getTarget()=vdev_90)
}

predicate func_4(Function func) {
	exists(IfStmt target_4 |
		target_4.getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("mt76x02_wait_for_mac")
		and target_4.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ValueFieldAccess).getTarget().getName()="mt76"
		and target_4.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier() instanceof PointerFieldAccess
		and target_4.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-110"
		and target_4.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getOperand().(Literal).getValue()="110"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_4)
}

predicate func_5(Parameter vdev_90, Function func) {
	exists(ExprStmt target_5 |
		target_5.getExpr().(FunctionCall).getTarget().hasName("mt76x02_dma_disable")
		and target_5.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdev_90
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_5)
}

predicate func_6(Parameter vdev_90, Variable verr_92, Function func) {
	exists(ExprStmt target_6 |
		target_6.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=verr_92
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("mt76x0e_mcu_init")
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdev_90
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_6)
}

predicate func_8(Parameter vdev_90, Variable verr_92, Function func) {
	exists(ExprStmt target_8 |
		target_8.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=verr_92
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("mt76x02_dma_init")
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdev_90
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_8)
}

predicate func_9(Parameter vdev_90, Variable verr_92, Function func) {
	exists(ExprStmt target_9 |
		target_9.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=verr_92
		and target_9.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("mt76x0_init_hardware")
		and target_9.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdev_90
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_9)
}

predicate func_10(Variable verr_92, Function func) {
	exists(IfStmt target_10 |
		target_10.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=verr_92
		and target_10.getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_10.getThen().(ReturnStmt).getExpr().(VariableAccess).getTarget()=verr_92
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_10)
}

predicate func_11(Parameter vdev_90, Function func) {
	exists(ExprStmt target_11 |
		target_11.getExpr().(FunctionCall).getTarget().hasName("mt76x02e_init_beacon_config")
		and target_11.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdev_90
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_11)
}

predicate func_12(Parameter vdev_90, Variable vval_114, Function func) {
	exists(IfStmt target_12 |
		target_12.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("mt76_chip")
		and target_12.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ValueFieldAccess).getTarget().getName()="mt76"
		and target_12.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="(unknown field)"
		and target_12.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdev_90
		and target_12.getCondition().(EqualityOperation).getAnOperand().(HexLiteral).getValue()="30224"
		and target_12.getThen().(BlockStmt).getStmt(0).(DeclStmt).getDeclarationEntry(0).(VariableDeclarationEntry).getType() instanceof CTypedefType
		and target_12.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(VariableCall).getExpr().(PointerFieldAccess).getTarget().getName()="rmw"
		and target_12.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(VariableCall).getExpr().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="bus"
		and target_12.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(VariableCall).getExpr().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="mt76"
		and target_12.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(VariableCall).getExpr().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="(unknown field)"
		and target_12.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(VariableCall).getExpr().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdev_90
		and target_12.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(VariableCall).getArgument(0).(AddressOfExpr).getOperand().(ValueFieldAccess).getTarget().getName()="mt76"
		and target_12.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(VariableCall).getArgument(0).(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="(unknown field)"
		and target_12.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(VariableCall).getArgument(0).(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdev_90
		and target_12.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(VariableCall).getArgument(1).(Literal).getValue()="64"
		and target_12.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(VariableCall).getArgument(2).(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1"
		and target_12.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(VariableCall).getArgument(2).(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="0"
		and target_12.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(VariableCall).getArgument(3).(Literal).getValue()="0"
		and target_12.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vval_114
		and target_12.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue() instanceof FunctionCall
		and target_12.getThen().(BlockStmt).getStmt(3).(IfStmt).getCondition().(NotExpr).getOperand().(BitwiseAndExpr).getLeftOperand().(VariableAccess).getTarget()=vval_114
		and target_12.getThen().(BlockStmt).getStmt(3).(IfStmt).getCondition().(NotExpr).getOperand().(BitwiseAndExpr).getRightOperand().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1"
		and target_12.getThen().(BlockStmt).getStmt(3).(IfStmt).getCondition().(NotExpr).getOperand().(BitwiseAndExpr).getRightOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="10"
		and target_12.getThen().(BlockStmt).getStmt(3).(IfStmt).getThen().(ExprStmt).getExpr().(VariableCall).getExpr().(PointerFieldAccess).getTarget().getName()="rmw"
		and target_12.getThen().(BlockStmt).getStmt(3).(IfStmt).getThen().(ExprStmt).getExpr().(VariableCall).getExpr().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="bus"
		and target_12.getThen().(BlockStmt).getStmt(3).(IfStmt).getThen().(ExprStmt).getExpr().(VariableCall).getExpr().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="mt76"
		and target_12.getThen().(BlockStmt).getStmt(3).(IfStmt).getThen().(ExprStmt).getExpr().(VariableCall).getExpr().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="(unknown field)"
		and target_12.getThen().(BlockStmt).getStmt(3).(IfStmt).getThen().(ExprStmt).getExpr().(VariableCall).getExpr().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdev_90
		and target_12.getThen().(BlockStmt).getStmt(3).(IfStmt).getThen().(ExprStmt).getExpr().(VariableCall).getArgument(0).(AddressOfExpr).getOperand().(ValueFieldAccess).getTarget().getName()="mt76"
		and target_12.getThen().(BlockStmt).getStmt(3).(IfStmt).getThen().(ExprStmt).getExpr().(VariableCall).getArgument(0).(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="(unknown field)"
		and target_12.getThen().(BlockStmt).getStmt(3).(IfStmt).getThen().(ExprStmt).getExpr().(VariableCall).getArgument(0).(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdev_90
		and target_12.getThen().(BlockStmt).getStmt(3).(IfStmt).getThen().(ExprStmt).getExpr().(VariableCall).getArgument(1).(Literal).getValue()="284"
		and target_12.getThen().(BlockStmt).getStmt(3).(IfStmt).getThen().(ExprStmt).getExpr().(VariableCall).getArgument(2).(Literal).getValue()="0"
		and target_12.getThen().(BlockStmt).getStmt(3).(IfStmt).getThen().(ExprStmt).getExpr().(VariableCall).getArgument(3).(Literal).getValue()="3075"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_12)
}

predicate func_17(Parameter vdev_90, Function func) {
	exists(ExprStmt target_17 |
		target_17.getExpr().(VariableCall).getExpr().(PointerFieldAccess).getTarget().getName()="rmw"
		and target_17.getExpr().(VariableCall).getExpr().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="bus"
		and target_17.getExpr().(VariableCall).getExpr().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="mt76"
		and target_17.getExpr().(VariableCall).getExpr().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="(unknown field)"
		and target_17.getExpr().(VariableCall).getExpr().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdev_90
		and target_17.getExpr().(VariableCall).getArgument(0).(AddressOfExpr).getOperand().(ValueFieldAccess).getTarget().getName()="mt76"
		and target_17.getExpr().(VariableCall).getArgument(0).(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="(unknown field)"
		and target_17.getExpr().(VariableCall).getArgument(0).(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdev_90
		and target_17.getExpr().(VariableCall).getArgument(1).(Literal).getValue()="272"
		and target_17.getExpr().(VariableCall).getArgument(2).(BinaryBitwiseOperation).getValue()="512"
		and target_17.getExpr().(VariableCall).getArgument(2).(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1"
		and target_17.getExpr().(VariableCall).getArgument(2).(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="9"
		and target_17.getExpr().(VariableCall).getArgument(3).(Literal).getValue()="0"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_17)
}

predicate func_18(Parameter vdev_90, Function func) {
	exists(ExprStmt target_18 |
		target_18.getExpr().(VariableCall).getExpr().(PointerFieldAccess).getTarget().getName()="rmw"
		and target_18.getExpr().(VariableCall).getExpr().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="bus"
		and target_18.getExpr().(VariableCall).getExpr().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="mt76"
		and target_18.getExpr().(VariableCall).getExpr().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="(unknown field)"
		and target_18.getExpr().(VariableCall).getExpr().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdev_90
		and target_18.getExpr().(VariableCall).getArgument(0).(AddressOfExpr).getOperand().(ValueFieldAccess).getTarget().getName()="mt76"
		and target_18.getExpr().(VariableCall).getArgument(0).(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="(unknown field)"
		and target_18.getExpr().(VariableCall).getArgument(0).(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdev_90
		and target_18.getExpr().(VariableCall).getArgument(1).(Literal).getValue()="4120"
		and target_18.getExpr().(VariableCall).getArgument(2).(Literal).getValue()="0"
		and target_18.getExpr().(VariableCall).getArgument(3).(BinaryBitwiseOperation).getValue()="8192"
		and target_18.getExpr().(VariableCall).getArgument(3).(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1"
		and target_18.getExpr().(VariableCall).getArgument(3).(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="13"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_18)
}

from Function func, Parameter vdev_90, Variable verr_92, Variable vval_114
where
func_1(vdev_90)
and func_2(vdev_90)
and func_3(vdev_90)
and func_4(func)
and func_5(vdev_90, func)
and func_6(vdev_90, verr_92, func)
and func_8(vdev_90, verr_92, func)
and func_9(vdev_90, verr_92, func)
and func_10(verr_92, func)
and func_11(vdev_90, func)
and func_12(vdev_90, vval_114, func)
and func_17(vdev_90, func)
and func_18(vdev_90, func)
and vdev_90.getType().hasName("mt76x02_dev *")
and verr_92.getType().hasName("int")
and vval_114.getType().hasName("u16")
and vdev_90.getParentScope+() = func
and verr_92.getParentScope+() = func
and vval_114.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
