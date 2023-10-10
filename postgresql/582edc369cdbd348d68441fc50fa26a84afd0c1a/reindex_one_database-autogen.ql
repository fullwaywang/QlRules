/**
 * @name postgresql-582edc369cdbd348d68441fc50fa26a84afd0c1a-reindex_one_database
 * @id cpp/postgresql/582edc369cdbd348d68441fc50fa26a84afd0c1a/reindex-one-database
 * @description postgresql-582edc369cdbd348d68441fc50fa26a84afd0c1a-src/bin/scripts/reindexdb.c-reindex_one_database CVE-2018-1058
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, StringLiteral target_0) {
		target_0.getValue()="REINDEX"
		and not target_0.getValue()="REINDEX "
		and target_0.getEnclosingFunction() = func
}

predicate func_1(Function func, StringLiteral target_1) {
		target_1.getValue()=" (VERBOSE)"
		and not target_1.getValue()="(VERBOSE) "
		and target_1.getEnclosingFunction() = func
}

predicate func_2(Parameter vname_275, Variable vsql_280, FunctionCall target_2) {
		target_2.getTarget().hasName("appendPQExpBuffer")
		and not target_2.getTarget().hasName("appendPQExpBufferStr")
		and target_2.getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vsql_280
		and target_2.getArgument(1).(StringLiteral).getValue()=" TABLE %s"
		and target_2.getArgument(2).(VariableAccess).getTarget()=vname_275
}

predicate func_3(Parameter vname_275, Variable vsql_280, FunctionCall target_3) {
		target_3.getTarget().hasName("appendPQExpBuffer")
		and not target_3.getTarget().hasName("appendPQExpBufferChar")
		and target_3.getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vsql_280
		and target_3.getArgument(1).(StringLiteral).getValue()=" INDEX %s"
		and target_3.getArgument(2).(VariableAccess).getTarget()=vname_275
}

predicate func_4(Parameter vname_275, Variable vsql_280, FunctionCall target_4) {
		target_4.getTarget().hasName("appendPQExpBuffer")
		and not target_4.getTarget().hasName("appendQualifiedRelation")
		and target_4.getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vsql_280
		and target_4.getArgument(1).(StringLiteral).getValue()=" SCHEMA %s"
		and target_4.getArgument(2).(VariableAccess).getTarget()=vname_275
}

predicate func_5(Variable vsql_280, FunctionCall target_5) {
		target_5.getTarget().hasName("appendPQExpBuffer")
		and not target_5.getTarget().hasName("appendPQExpBufferStr")
		and target_5.getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vsql_280
		and target_5.getArgument(1).(StringLiteral).getValue()=" DATABASE %s"
		and target_5.getArgument(2) instanceof FunctionCall
}

predicate func_7(Variable vsql_280, AddressOfExpr target_22, Function func) {
	exists(ExprStmt target_7 |
		target_7.getExpr().(FunctionCall).getTarget().hasName("appendPQExpBufferChar")
		and target_7.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vsql_280
		and target_7.getExpr().(FunctionCall).getArgument(1).(CharLiteral).getValue()="32"
		and (func.getEntryPoint().(BlockStmt).getStmt(7)=target_7 or func.getEntryPoint().(BlockStmt).getStmt(7).getFollowingStmt()=target_7)
		and target_22.getOperand().(VariableAccess).getLocation().isBefore(target_7.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getLocation()))
}

predicate func_9(ExprStmt target_23, Function func) {
	exists(LogicalOrExpr target_9 |
		target_9.getAnOperand() instanceof EqualityOperation
		and target_9.getAnOperand() instanceof EqualityOperation
		and target_9.getParent().(IfStmt).getThen()=target_23
		and target_9.getEnclosingFunction() = func)
}

predicate func_13(Variable vsql_280, AddressOfExpr target_24, AddressOfExpr target_25) {
	exists(FunctionCall target_13 |
		target_13.getTarget().hasName("appendPQExpBufferStr")
		and target_13.getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vsql_280
		and target_13.getArgument(1) instanceof FunctionCall
		and target_24.getOperand().(VariableAccess).getLocation().isBefore(target_13.getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getLocation())
		and target_13.getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getLocation().isBefore(target_25.getOperand().(VariableAccess).getLocation()))
}

predicate func_14(Parameter vtype_275, ExprStmt target_26, EqualityOperation target_14) {
		target_14.getAnOperand().(FunctionCall).getTarget().hasName("strcmp")
		and target_14.getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtype_275
		and target_14.getAnOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="SCHEMA"
		and target_14.getAnOperand().(Literal).getValue()="0"
		and target_14.getParent().(IfStmt).getThen()=target_26
}

predicate func_15(Parameter vtype_275, ExprStmt target_27, EqualityOperation target_15) {
		target_15.getAnOperand().(FunctionCall).getTarget().hasName("strcmp")
		and target_15.getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtype_275
		and target_15.getAnOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="DATABASE"
		and target_15.getAnOperand().(Literal).getValue()="0"
		and target_15.getParent().(IfStmt).getThen()=target_27
}

predicate func_16(Parameter vtype_275, ExprStmt target_23, EqualityOperation target_16) {
		target_16.getAnOperand().(FunctionCall).getTarget().hasName("strcmp")
		and target_16.getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtype_275
		and target_16.getAnOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="TABLE"
		and target_16.getAnOperand().(Literal).getValue()="0"
		and target_16.getParent().(IfStmt).getThen()=target_23
}

predicate func_17(Parameter vtype_275, ExprStmt target_28, EqualityOperation target_17) {
		target_17.getAnOperand().(FunctionCall).getTarget().hasName("strcmp")
		and target_17.getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtype_275
		and target_17.getAnOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="INDEX"
		and target_17.getAnOperand().(Literal).getValue()="0"
		and target_17.getParent().(IfStmt).getThen()=target_28
}

predicate func_18(Variable vconn_282, FunctionCall target_18) {
		target_18.getTarget().hasName("fmtId")
		and target_18.getArgument(0).(FunctionCall).getTarget().hasName("PQdb")
		and target_18.getArgument(0).(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vconn_282
		and target_18.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall
}

predicate func_19(Parameter vname_275, VariableAccess target_19) {
		target_19.getTarget()=vname_275
		and target_19.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall
}

predicate func_20(Parameter vname_275, VariableAccess target_20) {
		target_20.getTarget()=vname_275
		and target_20.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall
}

predicate func_21(EqualityOperation target_17, Function func, IfStmt target_21) {
		target_21.getCondition() instanceof EqualityOperation
		and target_21.getThen().(ExprStmt).getExpr() instanceof FunctionCall
		and target_21.getParent().(IfStmt).getParent().(IfStmt).getCondition()=target_17
		and target_21.getEnclosingFunction() = func
}

predicate func_22(Variable vsql_280, AddressOfExpr target_22) {
		target_22.getOperand().(VariableAccess).getTarget()=vsql_280
}

predicate func_23(ExprStmt target_23) {
		target_23.getExpr() instanceof FunctionCall
}

predicate func_24(Variable vsql_280, AddressOfExpr target_24) {
		target_24.getOperand().(VariableAccess).getTarget()=vsql_280
}

predicate func_25(Variable vsql_280, AddressOfExpr target_25) {
		target_25.getOperand().(VariableAccess).getTarget()=vsql_280
}

predicate func_26(ExprStmt target_26) {
		target_26.getExpr() instanceof FunctionCall
}

predicate func_27(ExprStmt target_27) {
		target_27.getExpr() instanceof FunctionCall
}

predicate func_28(ExprStmt target_28) {
		target_28.getExpr() instanceof FunctionCall
}

from Function func, Parameter vname_275, Parameter vtype_275, Variable vsql_280, Variable vconn_282, StringLiteral target_0, StringLiteral target_1, FunctionCall target_2, FunctionCall target_3, FunctionCall target_4, FunctionCall target_5, EqualityOperation target_14, EqualityOperation target_15, EqualityOperation target_16, EqualityOperation target_17, FunctionCall target_18, VariableAccess target_19, VariableAccess target_20, IfStmt target_21, AddressOfExpr target_22, ExprStmt target_23, AddressOfExpr target_24, AddressOfExpr target_25, ExprStmt target_26, ExprStmt target_27, ExprStmt target_28
where
func_0(func, target_0)
and func_1(func, target_1)
and func_2(vname_275, vsql_280, target_2)
and func_3(vname_275, vsql_280, target_3)
and func_4(vname_275, vsql_280, target_4)
and func_5(vsql_280, target_5)
and not func_7(vsql_280, target_22, func)
and not func_9(target_23, func)
and not func_13(vsql_280, target_24, target_25)
and func_14(vtype_275, target_26, target_14)
and func_15(vtype_275, target_27, target_15)
and func_16(vtype_275, target_23, target_16)
and func_17(vtype_275, target_28, target_17)
and func_18(vconn_282, target_18)
and func_19(vname_275, target_19)
and func_20(vname_275, target_20)
and func_21(target_17, func, target_21)
and func_22(vsql_280, target_22)
and func_23(target_23)
and func_24(vsql_280, target_24)
and func_25(vsql_280, target_25)
and func_26(target_26)
and func_27(target_27)
and func_28(target_28)
and vname_275.getType().hasName("const char *")
and vtype_275.getType().hasName("const char *")
and vsql_280.getType().hasName("PQExpBufferData")
and vconn_282.getType().hasName("PGconn *")
and vname_275.getFunction() = func
and vtype_275.getFunction() = func
and vsql_280.(LocalVariable).getFunction() = func
and vconn_282.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
