/**
 * @name ghostscript-79cccf641486a6595c43f1de1cd7ade696020a31-gs_nulldevice
 * @id cpp/ghostscript/79cccf641486a6595c43f1de1cd7ade696020a31/gs-nulldevice
 * @description ghostscript-79cccf641486a6595c43f1de1cd7ade696020a31-base/gsdevice.c-gs_nulldevice CVE-2018-16509
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vpgs_691, LogicalOrExpr target_2, ExprStmt target_3, ExprStmt target_4) {
	exists(IfStmt target_0 |
		target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="device"
		and target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpgs_691
		and target_0.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("bool")
		and target_0.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="LockSafetyParams"
		and target_0.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="device"
		and target_0.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpgs_691
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(3)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_2
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_4.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vpgs_691, LogicalOrExpr target_2, ExprStmt target_5) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="LockSafetyParams"
		and target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="device"
		and target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpgs_691
		and target_1.getExpr().(AssignExpr).getRValue().(VariableAccess).getType().hasName("bool")
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(7)=target_1
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_2
		and target_5.getExpr().(VariableCall).getExpr().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(Parameter vpgs_691, LogicalOrExpr target_2) {
		target_2.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="device"
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpgs_691
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_2.getAnOperand().(NotExpr).getOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="dname"
		and target_2.getAnOperand().(NotExpr).getOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="device"
		and target_2.getAnOperand().(NotExpr).getOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpgs_691
		and target_2.getAnOperand().(NotExpr).getOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="dname"
		and target_2.getAnOperand().(NotExpr).getOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("const gx_device_null")
}

predicate func_3(Parameter vpgs_691, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("int")
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("gs_copydevice")
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget().getType().hasName("gx_device *")
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget().getType().hasName("const gx_device_null")
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="memory"
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpgs_691
}

predicate func_4(Parameter vpgs_691, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="memory"
		and target_4.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="rc"
		and target_4.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("gx_device *")
		and target_4.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="memory"
		and target_4.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpgs_691
}

predicate func_5(Parameter vpgs_691, ExprStmt target_5) {
		target_5.getExpr().(VariableCall).getExpr().(ValueFieldAccess).getTarget().getName()="free_object"
		and target_5.getExpr().(VariableCall).getExpr().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="procs"
		and target_5.getExpr().(VariableCall).getExpr().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="memory"
		and target_5.getExpr().(VariableCall).getExpr().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpgs_691
		and target_5.getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="memory"
		and target_5.getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpgs_691
		and target_5.getExpr().(VariableCall).getArgument(1).(VariableAccess).getTarget().getType().hasName("gx_device *")
		and target_5.getExpr().(VariableCall).getArgument(2).(StringLiteral).getValue()="gs_copydevice(device)"
}

from Function func, Parameter vpgs_691, LogicalOrExpr target_2, ExprStmt target_3, ExprStmt target_4, ExprStmt target_5
where
not func_0(vpgs_691, target_2, target_3, target_4)
and not func_1(vpgs_691, target_2, target_5)
and func_2(vpgs_691, target_2)
and func_3(vpgs_691, target_3)
and func_4(vpgs_691, target_4)
and func_5(vpgs_691, target_5)
and vpgs_691.getType().hasName("gs_gstate *")
and vpgs_691.getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
