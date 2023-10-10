/**
 * @name postgresql-b048f558dd7c26a0c630a2cff29d3d8981eaf6b9-ExecAlterObjectDependsStmt
 * @id cpp/postgresql/b048f558dd7c26a0c630a2cff29d3d8981eaf6b9/ExecAlterObjectDependsStmt
 * @description postgresql-b048f558dd7c26a0c630a2cff29d3d8981eaf6b9-src/backend/commands/alter.c-ExecAlterObjectDependsStmt CVE-2020-1720
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vaddress_433, Variable vrel_435, Parameter vstmt_431/*, ExprStmt target_1, AddressOfExpr target_2, AddressOfExpr target_3, IfStmt target_4, ExprStmt target_5, Function func*/) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("check_object_ownership")
		and target_0.getExpr().(FunctionCall).getArgument(0).(FunctionCall).getTarget().hasName("GetUserId")
		and target_0.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="objectType"
		and target_0.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstmt_431
		and target_0.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vaddress_433
		and target_0.getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getTarget().getName()="object"
		and target_0.getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstmt_431
		and target_0.getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vrel_435
		/*and (func.getEntryPoint().(BlockStmt).getStmt(4)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(4).getFollowingStmt()=target_0)
		and target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getLocation())
		and target_0.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getLocation().isBefore(target_2.getOperand().(VariableAccess).getLocation())
		and target_3.getOperand().(VariableAccess).getLocation().isBefore(target_0.getExpr().(FunctionCall).getArgument(4).(VariableAccess).getLocation())
		and target_0.getExpr().(FunctionCall).getArgument(4).(VariableAccess).getLocation().isBefore(target_4.getCondition().(VariableAccess).getLocation())
		and target_0.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())*/)
}

predicate func_1(Variable vaddress_433, Variable vrel_435, Parameter vstmt_431, ExprStmt target_1) {
		target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vaddress_433
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("get_object_address_rv")
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="objectType"
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstmt_431
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="relation"
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstmt_431
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="object"
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstmt_431
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vrel_435
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(Literal).getValue()="8"
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(Literal).getValue()="0"
}

predicate func_2(Variable vaddress_433, AddressOfExpr target_2) {
		target_2.getOperand().(VariableAccess).getTarget()=vaddress_433
}

predicate func_3(Variable vrel_435, AddressOfExpr target_3) {
		target_3.getOperand().(VariableAccess).getTarget()=vrel_435
}

predicate func_4(Variable vrel_435, IfStmt target_4) {
		target_4.getCondition().(VariableAccess).getTarget()=vrel_435
		and target_4.getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("table_close")
		and target_4.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vrel_435
		and target_4.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
}

predicate func_5(Variable vrel_435, Parameter vstmt_431, ExprStmt target_5) {
		target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("ObjectAddress")
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("get_object_address")
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="extname"
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstmt_431
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vrel_435
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(Literal).getValue()="8"
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(Literal).getValue()="0"
}

from Function func, Variable vaddress_433, Variable vrel_435, Parameter vstmt_431, ExprStmt target_1, AddressOfExpr target_2, AddressOfExpr target_3, IfStmt target_4, ExprStmt target_5
where
not func_0(vaddress_433, vrel_435, vstmt_431/*, target_1, target_2, target_3, target_4, target_5, func*/)
and func_1(vaddress_433, vrel_435, vstmt_431, target_1)
and func_2(vaddress_433, target_2)
and func_3(vrel_435, target_3)
and func_4(vrel_435, target_4)
and func_5(vrel_435, vstmt_431, target_5)
and vaddress_433.getType().hasName("ObjectAddress")
and vrel_435.getType().hasName("Relation")
and vstmt_431.getType().hasName("AlterObjectDependsStmt *")
and vaddress_433.(LocalVariable).getFunction() = func
and vrel_435.(LocalVariable).getFunction() = func
and vstmt_431.getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
