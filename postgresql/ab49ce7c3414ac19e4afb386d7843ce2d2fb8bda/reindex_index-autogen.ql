/**
 * @name postgresql-ab49ce7c3414ac19e4afb386d7843ce2d2fb8bda-reindex_index
 * @id cpp/postgresql/ab49ce7c3414ac19e4afb386d7843ce2d2fb8bda/reindex-index
 * @description postgresql-ab49ce7c3414ac19e4afb386d7843ce2d2fb8bda-src/backend/catalog/index.c-reindex_index CVE-2022-1552
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("GetUserIdAndSecContext")
		and target_0.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("Oid")
		and target_0.getExpr().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("int")
		and (func.getEntryPoint().(BlockStmt).getStmt(15)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(15).getFollowingStmt()=target_0))
}

predicate func_1(Variable vheapRelation_3526, NotExpr target_5, ExprStmt target_6, Function func) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(FunctionCall).getTarget().hasName("SetUserIdAndSecContext")
		and target_1.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="relowner"
		and target_1.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="rd_rel"
		and target_1.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vheapRelation_3526
		and target_1.getExpr().(FunctionCall).getArgument(1).(BitwiseOrExpr).getLeftOperand().(VariableAccess).getType().hasName("int")
		and target_1.getExpr().(FunctionCall).getArgument(1).(BitwiseOrExpr).getRightOperand().(Literal).getValue()="2"
		and (func.getEntryPoint().(BlockStmt).getStmt(16)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(16).getFollowingStmt()=target_1)
		and target_5.getOperand().(VariableAccess).getLocation().isBefore(target_1.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_1.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_6.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_2(Function func) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("int")
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("NewGUCNestLevel")
		and (func.getEntryPoint().(BlockStmt).getStmt(17)=target_2 or func.getEntryPoint().(BlockStmt).getStmt(17).getFollowingStmt()=target_2))
}

predicate func_3(Function func) {
	exists(ExprStmt target_3 |
		target_3.getExpr().(FunctionCall).getTarget().hasName("AtEOXact_GUC")
		and target_3.getExpr().(FunctionCall).getArgument(0).(Literal).getValue()="0"
		and target_3.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getType().hasName("int")
		and (func.getEntryPoint().(BlockStmt).getStmt(37)=target_3 or func.getEntryPoint().(BlockStmt).getStmt(37).getFollowingStmt()=target_3))
}

predicate func_4(Function func) {
	exists(ExprStmt target_4 |
		target_4.getExpr().(FunctionCall).getTarget().hasName("SetUserIdAndSecContext")
		and target_4.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getType().hasName("Oid")
		and target_4.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getType().hasName("int")
		and (func.getEntryPoint().(BlockStmt).getStmt(38)=target_4 or func.getEntryPoint().(BlockStmt).getStmt(38).getFollowingStmt()=target_4))
}

predicate func_5(Variable vheapRelation_3526, NotExpr target_5) {
		target_5.getOperand().(VariableAccess).getTarget()=vheapRelation_3526
}

predicate func_6(Variable vheapRelation_3526, ExprStmt target_6) {
		target_6.getExpr().(FunctionCall).getTarget().hasName("index_build")
		and target_6.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vheapRelation_3526
		and target_6.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget().getType().hasName("Relation")
		and target_6.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget().getType().hasName("IndexInfo *")
		and target_6.getExpr().(FunctionCall).getArgument(3).(Literal).getValue()="1"
		and target_6.getExpr().(FunctionCall).getArgument(4).(Literal).getValue()="1"
}

from Function func, Variable vheapRelation_3526, NotExpr target_5, ExprStmt target_6
where
not func_0(func)
and not func_1(vheapRelation_3526, target_5, target_6, func)
and not func_2(func)
and not func_3(func)
and not func_4(func)
and func_5(vheapRelation_3526, target_5)
and func_6(vheapRelation_3526, target_6)
and vheapRelation_3526.getType().hasName("Relation")
and vheapRelation_3526.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
