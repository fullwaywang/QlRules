/**
 * @name bluez-87184a20cfcfe1523926a2e4a724c1a01c7ae0fb-gatt_db_attribute_read
 * @id cpp/bluez/87184a20cfcfe1523926a2e4a724c1a01c7ae0fb/gatt-db-attribute-read
 * @description bluez-87184a20cfcfe1523926a2e4a724c1a01c7ae0fb-src/shared/gatt-db.c-gatt_db_attribute_read CVE-2021-3588
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vattrib_1839, BlockStmt target_2, ExprStmt target_3, RelationalOperation target_1) {
	exists(LogicalAndExpr target_0 |
		target_0.getAnOperand().(PointerFieldAccess).getTarget().getName()="value_len"
		and target_0.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vattrib_1839
		and target_0.getAnOperand() instanceof RelationalOperation
		and target_0.getParent().(IfStmt).getThen()=target_2
		and target_3.getExpr().(VariableCall).getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vattrib_1839, Parameter voffset_1839, BlockStmt target_2, RelationalOperation target_1) {
		 (target_1 instanceof GTExpr or target_1 instanceof LTExpr)
		and target_1.getGreaterOperand().(VariableAccess).getTarget()=voffset_1839
		and target_1.getLesserOperand().(PointerFieldAccess).getTarget().getName()="value_len"
		and target_1.getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vattrib_1839
		and target_1.getParent().(IfStmt).getThen()=target_2
}

predicate func_2(Parameter vattrib_1839, BlockStmt target_2) {
		target_2.getStmt(0).(ExprStmt).getExpr().(VariableCall).getArgument(0).(VariableAccess).getTarget()=vattrib_1839
		and target_2.getStmt(0).(ExprStmt).getExpr().(VariableCall).getArgument(1).(Literal).getValue()="7"
		and target_2.getStmt(0).(ExprStmt).getExpr().(VariableCall).getArgument(2).(Literal).getValue()="0"
		and target_2.getStmt(0).(ExprStmt).getExpr().(VariableCall).getArgument(3).(Literal).getValue()="0"
		and target_2.getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="1"
}

predicate func_3(Parameter vattrib_1839, Parameter voffset_1839, ExprStmt target_3) {
		target_3.getExpr().(VariableCall).getExpr().(PointerFieldAccess).getTarget().getName()="read_func"
		and target_3.getExpr().(VariableCall).getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vattrib_1839
		and target_3.getExpr().(VariableCall).getArgument(0).(VariableAccess).getTarget()=vattrib_1839
		and target_3.getExpr().(VariableCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="id"
		and target_3.getExpr().(VariableCall).getArgument(2).(VariableAccess).getTarget()=voffset_1839
		and target_3.getExpr().(VariableCall).getArgument(5).(PointerFieldAccess).getTarget().getName()="user_data"
		and target_3.getExpr().(VariableCall).getArgument(5).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vattrib_1839
}

from Function func, Parameter vattrib_1839, Parameter voffset_1839, RelationalOperation target_1, BlockStmt target_2, ExprStmt target_3
where
not func_0(vattrib_1839, target_2, target_3, target_1)
and func_1(vattrib_1839, voffset_1839, target_2, target_1)
and func_2(vattrib_1839, target_2)
and func_3(vattrib_1839, voffset_1839, target_3)
and vattrib_1839.getType().hasName("gatt_db_attribute *")
and voffset_1839.getType().hasName("uint16_t")
and vattrib_1839.getParentScope+() = func
and voffset_1839.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
