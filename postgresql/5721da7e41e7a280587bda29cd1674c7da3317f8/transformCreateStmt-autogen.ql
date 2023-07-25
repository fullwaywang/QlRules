/**
 * @name postgresql-5721da7e41e7a280587bda29cd1674c7da3317f8-transformCreateStmt
 * @id cpp/postgresql/5721da7e41e7a280587bda29cd1674c7da3317f8/transformCreateStmt
 * @description postgresql-5721da7e41e7a280587bda29cd1674c7da3317f8-src/backend/parser/parse_utilcmd.c-transformCreateStmt CVE-2022-2625
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vexisting_relid_173, LogicalAndExpr target_2) {
	exists(DoStmt target_0 |
		target_0.getCondition().(Literal).getValue()="0"
		and target_0.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="classId"
		and target_0.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(VariableAccess).getType().hasName("ObjectAddress")
		and target_0.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="1259"
		and target_0.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="objectId"
		and target_0.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(VariableAccess).getType().hasName("ObjectAddress")
		and target_0.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vexisting_relid_173
		and target_0.getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="objectSubId"
		and target_0.getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(VariableAccess).getType().hasName("ObjectAddress")
		and target_0.getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_2)
}

predicate func_1(LogicalAndExpr target_2, Function func) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(FunctionCall).getTarget().hasName("checkMembershipInCurrentExtension")
		and target_1.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("ObjectAddress")
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(2)=target_1
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_2
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(Variable vexisting_relid_173, LogicalAndExpr target_2) {
		target_2.getAnOperand().(PointerFieldAccess).getTarget().getName()="if_not_exists"
		and target_2.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("CreateStmt *")
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vexisting_relid_173
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
}

from Function func, Variable vexisting_relid_173, LogicalAndExpr target_2
where
not func_0(vexisting_relid_173, target_2)
and not func_1(target_2, func)
and func_2(vexisting_relid_173, target_2)
and vexisting_relid_173.getType().hasName("Oid")
and vexisting_relid_173.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
