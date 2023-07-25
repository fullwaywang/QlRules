/**
 * @name openssl-63658103d4441924f8dbfc517b99bb54758a98b9-ssl3_read_bytes
 * @id cpp/openssl/63658103d4441924f8dbfc517b99bb54758a98b9/ssl3-read-bytes
 * @description openssl-63658103d4441924f8dbfc517b99bb54758a98b9-ssl/record/rec_layer_s3.c-ssl3_read_bytes CVE-2016-6305
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vrr_968, NotExpr target_2, AddressOfExpr target_3, ExprStmt target_4) {
	exists(IfStmt target_0 |
		target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="length"
		and target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrr_968
		and target_0.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="read"
		and target_0.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrr_968
		and target_0.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_2
		and target_3.getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_4.getExpr().(AssignSubExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vpeek_964, BlockStmt target_5, VariableAccess target_1) {
		target_1.getTarget()=vpeek_964
		and target_1.getParent().(NotExpr).getParent().(IfStmt).getThen()=target_5
}

predicate func_2(Parameter vpeek_964, BlockStmt target_5, LogicalOrExpr target_6, LogicalOrExpr target_7, NotExpr target_2) {
		target_2.getOperand().(VariableAccess).getTarget()=vpeek_964
		and target_2.getParent().(IfStmt).getThen()=target_5
		and target_6.getAnOperand().(LogicalAndExpr).getAnOperand().(VariableAccess).getLocation().isBefore(target_2.getOperand().(VariableAccess).getLocation())
		and target_2.getOperand().(VariableAccess).getLocation().isBefore(target_7.getAnOperand().(LogicalAndExpr).getAnOperand().(VariableAccess).getLocation())
}

predicate func_3(Variable vrr_968, AddressOfExpr target_3) {
		target_3.getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="data"
		and target_3.getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrr_968
		and target_3.getOperand().(ArrayExpr).getArrayOffset().(PointerFieldAccess).getTarget().getName()="off"
		and target_3.getOperand().(ArrayExpr).getArrayOffset().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrr_968
}

predicate func_4(Variable vrr_968, ExprStmt target_4) {
		target_4.getExpr().(AssignSubExpr).getLValue().(PointerFieldAccess).getTarget().getName()="length"
		and target_4.getExpr().(AssignSubExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrr_968
}

predicate func_5(Variable vrr_968, BlockStmt target_5) {
		target_5.getStmt(0).(ExprStmt).getExpr().(AssignSubExpr).getLValue().(PointerFieldAccess).getTarget().getName()="length"
		and target_5.getStmt(0).(ExprStmt).getExpr().(AssignSubExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrr_968
		and target_5.getStmt(1).(ExprStmt).getExpr().(AssignAddExpr).getLValue().(PointerFieldAccess).getTarget().getName()="off"
		and target_5.getStmt(1).(ExprStmt).getExpr().(AssignAddExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrr_968
		and target_5.getStmt(2).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="length"
		and target_5.getStmt(2).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrr_968
		and target_5.getStmt(2).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_5.getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="rstate"
		and target_5.getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="rlayer"
		and target_5.getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="240"
		and target_5.getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="off"
		and target_5.getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrr_968
		and target_5.getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
}

predicate func_6(Parameter vpeek_964, LogicalOrExpr target_6) {
		target_6.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="23"
		and target_6.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="22"
		and target_6.getAnOperand().(LogicalAndExpr).getAnOperand().(VariableAccess).getTarget()=vpeek_964
		and target_6.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="23"
}

predicate func_7(Parameter vpeek_964, Variable vrr_968, LogicalOrExpr target_7) {
		target_7.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="length"
		and target_7.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrr_968
		and target_7.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_7.getAnOperand().(LogicalAndExpr).getAnOperand().(VariableAccess).getTarget()=vpeek_964
		and target_7.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="length"
		and target_7.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrr_968
}

from Function func, Parameter vpeek_964, Variable vrr_968, VariableAccess target_1, NotExpr target_2, AddressOfExpr target_3, ExprStmt target_4, BlockStmt target_5, LogicalOrExpr target_6, LogicalOrExpr target_7
where
not func_0(vrr_968, target_2, target_3, target_4)
and func_1(vpeek_964, target_5, target_1)
and func_2(vpeek_964, target_5, target_6, target_7, target_2)
and func_3(vrr_968, target_3)
and func_4(vrr_968, target_4)
and func_5(vrr_968, target_5)
and func_6(vpeek_964, target_6)
and func_7(vpeek_964, vrr_968, target_7)
and vpeek_964.getType().hasName("int")
and vrr_968.getType().hasName("SSL3_RECORD *")
and vpeek_964.getParentScope+() = func
and vrr_968.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
