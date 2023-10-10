/**
 * @name postgresql-5721da7e41e7a280587bda29cd1674c7da3317f8-CreateTableAsRelExists
 * @id cpp/postgresql/5721da7e41e7a280587bda29cd1674c7da3317f8/CreateTableAsRelExists
 * @description postgresql-5721da7e41e7a280587bda29cd1674c7da3317f8-src/backend/commands/createas.c-CreateTableAsRelExists CVE-2022-2625
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("Oid")
		and target_0.getExpr().(AssignExpr).getRValue() instanceof FunctionCall
		and (func.getEntryPoint().(BlockStmt).getStmt(5)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(5).getFollowingStmt()=target_0))
}

predicate func_1(BlockStmt target_5, Function func) {
	exists(EqualityOperation target_1 |
		target_1.getAnOperand().(VariableAccess).getType().hasName("Oid")
		and target_1.getAnOperand().(Literal).getValue()="0"
		and target_1.getParent().(IfStmt).getThen()=target_5
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(FunctionCall target_4, Function func) {
	exists(DoStmt target_2 |
		target_2.getCondition().(Literal).getValue()="0"
		and target_2.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="classId"
		and target_2.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(VariableAccess).getType().hasName("ObjectAddress")
		and target_2.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="1259"
		and target_2.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="objectId"
		and target_2.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(VariableAccess).getType().hasName("ObjectAddress")
		and target_2.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getType().hasName("Oid")
		and target_2.getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="objectSubId"
		and target_2.getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(VariableAccess).getType().hasName("ObjectAddress")
		and target_2.getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_2
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_4
		and target_2.getEnclosingFunction() = func)
}

predicate func_3(FunctionCall target_4, Function func) {
	exists(ExprStmt target_3 |
		target_3.getExpr().(FunctionCall).getTarget().hasName("checkMembershipInCurrentExtension")
		and target_3.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("ObjectAddress")
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(2)=target_3
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_4
		and target_3.getEnclosingFunction() = func)
}

predicate func_4(Variable vnspid_395, Variable vinto_396, BlockStmt target_5, FunctionCall target_4) {
		target_4.getTarget().hasName("get_relname_relid")
		and target_4.getArgument(0).(PointerFieldAccess).getTarget().getName()="relname"
		and target_4.getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="rel"
		and target_4.getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vinto_396
		and target_4.getArgument(1).(VariableAccess).getTarget()=vnspid_395
		and target_4.getParent().(IfStmt).getThen()=target_5
}

predicate func_5(BlockStmt target_5) {
		target_5.getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(PointerFieldAccess).getTarget().getName()="if_not_exists"
		and target_5.getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("CreateTableAsStmt *")
		and target_5.getStmt(0).(IfStmt).getThen().(DoStmt).getCondition() instanceof Literal
		and target_5.getStmt(0).(IfStmt).getThen().(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(ConditionalExpr).getThen().(FunctionCall).getTarget().hasName("errstart_cold")
		and target_5.getStmt(0).(IfStmt).getThen().(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(ConditionalExpr).getElse().(FunctionCall).getTarget().hasName("errstart")
		and target_5.getStmt(0).(IfStmt).getThen().(DoStmt).getStmt().(BlockStmt).getStmt(2).(IfStmt).getCondition().(LogicalAndExpr).getValue()="1"
		and target_5.getStmt(0).(IfStmt).getThen().(DoStmt).getStmt().(BlockStmt).getStmt(2).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("__builtin_unreachable")
}

from Function func, Variable vnspid_395, Variable vinto_396, FunctionCall target_4, BlockStmt target_5
where
not func_0(func)
and not func_1(target_5, func)
and not func_2(target_4, func)
and not func_3(target_4, func)
and func_4(vnspid_395, vinto_396, target_5, target_4)
and func_5(target_5)
and vnspid_395.getType().hasName("Oid")
and vinto_396.getType().hasName("IntoClause *")
and vnspid_395.(LocalVariable).getFunction() = func
and vinto_396.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
