/**
 * @name postgresql-ab49ce7c3414ac19e4afb386d7843ce2d2fb8bda-cluster_rel
 * @id cpp/postgresql/ab49ce7c3414ac19e4afb386d7843ce2d2fb8bda/cluster-rel
 * @description postgresql-ab49ce7c3414ac19e4afb386d7843ce2d2fb8bda-src/backend/commands/cluster.c-cluster_rel CVE-2022-1552
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, FunctionCall target_0) {
		target_0.getTarget().hasName("pgstat_progress_end_command")
		and not target_0.getTarget().hasName("GetUserIdAndSecContext")
		and target_0.getEnclosingFunction() = func
}

predicate func_1(Function func, FunctionCall target_1) {
		target_1.getTarget().hasName("pgstat_progress_end_command")
		and not target_1.getTarget().hasName("SetUserIdAndSecContext")
		and target_1.getEnclosingFunction() = func
}

predicate func_2(Function func, FunctionCall target_2) {
		target_2.getTarget().hasName("pgstat_progress_end_command")
		and not target_2.getTarget().hasName("AtEOXact_GUC")
		and target_2.getEnclosingFunction() = func
}

predicate func_3(Function func, FunctionCall target_3) {
		target_3.getTarget().hasName("pgstat_progress_end_command")
		and not target_3.getTarget().hasName("SetUserIdAndSecContext")
		and target_3.getEnclosingFunction() = func
}

predicate func_4(Function func) {
	exists(AddressOfExpr target_4 |
		target_4.getOperand().(VariableAccess).getType().hasName("Oid")
		and target_4.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall
		and target_4.getEnclosingFunction() = func)
}

predicate func_5(Function func) {
	exists(AddressOfExpr target_5 |
		target_5.getOperand().(VariableAccess).getType().hasName("int")
		and target_5.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall
		and target_5.getEnclosingFunction() = func)
}

predicate func_6(Variable vOldHeap_279, ExprStmt target_29, ExprStmt target_30) {
	exists(PointerFieldAccess target_6 |
		target_6.getTarget().getName()="relowner"
		and target_6.getQualifier().(PointerFieldAccess).getTarget().getName()="rd_rel"
		and target_6.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vOldHeap_279
		and target_29.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_6.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_6.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_30.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_7(Function func) {
	exists(BitwiseOrExpr target_7 |
		target_7.getLeftOperand().(VariableAccess).getType().hasName("int")
		and target_7.getRightOperand().(Literal).getValue()="2"
		and target_7.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall
		and target_7.getEnclosingFunction() = func)
}

predicate func_8(Function func) {
	exists(AssignExpr target_8 |
		target_8.getLValue().(VariableAccess).getType().hasName("int")
		and target_8.getRValue().(FunctionCall).getTarget().hasName("NewGUCNestLevel")
		and target_8.getEnclosingFunction() = func)
}

predicate func_10(NotExpr target_31, Function func) {
	exists(GotoStmt target_10 |
		target_10.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_10
		and target_10.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_31
		and target_10.getEnclosingFunction() = func)
}

predicate func_11(LogicalAndExpr target_32, Function func) {
	exists(GotoStmt target_11 |
		target_11.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_11
		and target_11.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_32
		and target_11.getEnclosingFunction() = func)
}

predicate func_12(NotExpr target_33, Function func) {
	exists(GotoStmt target_12 |
		target_12.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_12
		and target_12.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_33
		and target_12.getEnclosingFunction() = func)
}

predicate func_13(NotExpr target_34, Function func) {
	exists(GotoStmt target_13 |
		target_13.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_13
		and target_13.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_34
		and target_13.getEnclosingFunction() = func)
}

predicate func_14(LogicalAndExpr target_35, Function func) {
	exists(GotoStmt target_14 |
		target_14.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_14
		and target_14.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_35
		and target_14.getEnclosingFunction() = func)
}

predicate func_15(Function func) {
	exists(LabelStmt target_15 |
		(func.getEntryPoint().(BlockStmt).getStmt(22)=target_15 or func.getEntryPoint().(BlockStmt).getStmt(22).getFollowingStmt()=target_15))
}

predicate func_20(NotExpr target_31, Function func, ExprStmt target_20) {
		target_20.getExpr().(FunctionCall).getTarget().hasName("pgstat_progress_end_command")
		and target_20.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_31
		and target_20.getEnclosingFunction() = func
}

predicate func_21(NotExpr target_31, Function func, ReturnStmt target_21) {
		target_21.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_31
		and target_21.getEnclosingFunction() = func
}

predicate func_22(Function func, FunctionCall target_22) {
		target_22.getTarget().hasName("GetUserId")
		and target_22.getParent().(FunctionCall).getParent().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("pg_class_ownercheck")
		and target_22.getParent().(FunctionCall).getParent().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("Oid")
		and target_22.getEnclosingFunction() = func
}

predicate func_23(LogicalAndExpr target_32, Function func, ReturnStmt target_23) {
		target_23.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_32
		and target_23.getEnclosingFunction() = func
}

predicate func_24(NotExpr target_33, Function func, ReturnStmt target_24) {
		target_24.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_33
		and target_24.getEnclosingFunction() = func
}

predicate func_25(NotExpr target_34, Function func, ReturnStmt target_25) {
		target_25.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_34
		and target_25.getEnclosingFunction() = func
}

predicate func_26(LogicalAndExpr target_35, Function func, ReturnStmt target_26) {
		target_26.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_35
		and target_26.getEnclosingFunction() = func
}

predicate func_27(Function func, FunctionCall target_27) {
		target_27.getTarget().hasName("pgstat_progress_end_command")
		and target_27.getEnclosingFunction() = func
}

predicate func_28(Function func, ReturnStmt target_28) {
		func.getEntryPoint().(BlockStmt).getAStmt()=target_28
}

predicate func_29(Variable vOldHeap_279, ExprStmt target_29) {
		target_29.getExpr().(FunctionCall).getTarget().hasName("relation_close")
		and target_29.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vOldHeap_279
		and target_29.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="8"
}

predicate func_30(Variable vOldHeap_279, ExprStmt target_30) {
		target_30.getExpr().(FunctionCall).getTarget().hasName("relation_close")
		and target_30.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vOldHeap_279
		and target_30.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="8"
}

predicate func_31(NotExpr target_31) {
		target_31.getOperand().(FunctionCall).getTarget().hasName("pg_class_ownercheck")
		and target_31.getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("Oid")
		and target_31.getOperand().(FunctionCall).getArgument(1) instanceof FunctionCall
}

predicate func_32(Variable vOldHeap_279, LogicalAndExpr target_32) {
		target_32.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="relpersistence"
		and target_32.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="rd_rel"
		and target_32.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vOldHeap_279
		and target_32.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="116"
		and target_32.getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getTarget().getName()="rd_islocaltemp"
		and target_32.getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vOldHeap_279
}

predicate func_33(NotExpr target_33) {
		target_33.getOperand().(FunctionCall).getTarget().hasName("SearchSysCacheExists")
		and target_33.getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget().getType().hasName("Oid")
		and target_33.getOperand().(FunctionCall).getArgument(2).(Literal).getValue()="0"
		and target_33.getOperand().(FunctionCall).getArgument(3).(Literal).getValue()="0"
		and target_33.getOperand().(FunctionCall).getArgument(4).(Literal).getValue()="0"
}

predicate func_34(NotExpr target_34) {
		target_34.getOperand().(FunctionCall).getTarget().hasName("get_index_isclustered")
		and target_34.getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("Oid")
}

predicate func_35(Variable vOldHeap_279, LogicalAndExpr target_35) {
		target_35.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="relkind"
		and target_35.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="rd_rel"
		and target_35.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vOldHeap_279
		and target_35.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="109"
		and target_35.getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getTarget().getName()="relispopulated"
		and target_35.getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="rd_rel"
		and target_35.getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vOldHeap_279
}

from Function func, Variable vOldHeap_279, FunctionCall target_0, FunctionCall target_1, FunctionCall target_2, FunctionCall target_3, ExprStmt target_20, ReturnStmt target_21, FunctionCall target_22, ReturnStmt target_23, ReturnStmt target_24, ReturnStmt target_25, ReturnStmt target_26, FunctionCall target_27, ReturnStmt target_28, ExprStmt target_29, ExprStmt target_30, NotExpr target_31, LogicalAndExpr target_32, NotExpr target_33, NotExpr target_34, LogicalAndExpr target_35
where
func_0(func, target_0)
and func_1(func, target_1)
and func_2(func, target_2)
and func_3(func, target_3)
and not func_4(func)
and not func_5(func)
and not func_6(vOldHeap_279, target_29, target_30)
and not func_7(func)
and not func_8(func)
and not func_10(target_31, func)
and not func_11(target_32, func)
and not func_12(target_33, func)
and not func_13(target_34, func)
and not func_14(target_35, func)
and not func_15(func)
and func_20(target_31, func, target_20)
and func_21(target_31, func, target_21)
and func_22(func, target_22)
and func_23(target_32, func, target_23)
and func_24(target_33, func, target_24)
and func_25(target_34, func, target_25)
and func_26(target_35, func, target_26)
and func_27(func, target_27)
and func_28(func, target_28)
and func_29(vOldHeap_279, target_29)
and func_30(vOldHeap_279, target_30)
and func_31(target_31)
and func_32(vOldHeap_279, target_32)
and func_33(target_33)
and func_34(target_34)
and func_35(vOldHeap_279, target_35)
and vOldHeap_279.getType().hasName("Relation")
and vOldHeap_279.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
