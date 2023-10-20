/**
 * @name postgresql-a117cebd638dd02e5c2e791c25e43745f233111b-DefineIndex
 * @id cpp/postgresql/a117cebd638dd02e5c2e791c25e43745f233111b/DefineIndex
 * @description postgresql-a117cebd638dd02e5c2e791c25e43745f233111b-src/backend/commands/indexcmds.c-DefineIndex CVE-2022-1552
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vsave_nestlevel_550, VariableAccess target_0) {
		target_0.getTarget()=vsave_nestlevel_550
		and target_0.getParent().(AssignExpr).getLValue() = target_0
		and target_0.getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("NewGUCNestLevel")
}

predicate func_1(Variable vsave_nestlevel_550, RelationalOperation target_47, Literal target_1) {
		target_1.getValue()="1"
		and not target_1.getValue()="0"
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("AtEOXact_GUC")
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vsave_nestlevel_550
		and target_47.getGreaterOperand().(VariableAccess).getLocation().isBefore(target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation())
}

/*predicate func_2(Variable vsave_nestlevel_550, VariableAccess target_2) {
		target_2.getTarget()=vsave_nestlevel_550
		and target_2.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("AtEOXact_GUC")
		and target_2.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(Literal).getValue()="1"
}

*/
predicate func_3(Variable vsave_nestlevel_550, ExprStmt target_49, VariableAccess target_3) {
		target_3.getTarget()=vsave_nestlevel_550
		and target_3.getParent().(GEExpr).getLesserOperand() instanceof Literal
		and target_3.getParent().(GEExpr).getParent().(IfStmt).getThen()=target_49
}

predicate func_5(Function func) {
	exists(ExprStmt target_5 |
		target_5.getExpr().(FunctionCall).getTarget().hasName("GetUserIdAndSecContext")
		and target_5.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("Oid")
		and target_5.getExpr().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("int")
		and (func.getEntryPoint().(BlockStmt).getStmt(49)=target_5 or func.getEntryPoint().(BlockStmt).getStmt(49).getFollowingStmt()=target_5))
}

predicate func_6(Variable vrel_529, ExprStmt target_50, PointerFieldAccess target_51, Function func) {
	exists(ExprStmt target_6 |
		target_6.getExpr().(FunctionCall).getTarget().hasName("SetUserIdAndSecContext")
		and target_6.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="relowner"
		and target_6.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="rd_rel"
		and target_6.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrel_529
		and target_6.getExpr().(FunctionCall).getArgument(1).(BitwiseOrExpr).getLeftOperand().(VariableAccess).getType().hasName("int")
		and target_6.getExpr().(FunctionCall).getArgument(1).(BitwiseOrExpr).getRightOperand().(Literal).getValue()="2"
		and (func.getEntryPoint().(BlockStmt).getStmt(50)=target_6 or func.getEntryPoint().(BlockStmt).getStmt(50).getFollowingStmt()=target_6)
		and target_50.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_6.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_6.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_51.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_9(NotExpr target_38, Function func) {
	exists(ExprStmt target_9 |
		target_9.getExpr().(FunctionCall).getTarget().hasName("SetUserIdAndSecContext")
		and target_9.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getType().hasName("Oid")
		and target_9.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getType().hasName("int")
		and target_9.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_9
		and target_9.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_38
		and target_9.getEnclosingFunction() = func)
}

predicate func_10(Function func) {
	exists(ExprStmt target_10 |
		target_10.getExpr().(FunctionCall).getTarget().hasName("AtEOXact_GUC")
		and target_10.getExpr().(FunctionCall).getArgument(0) instanceof Literal
		and target_10.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getType().hasName("int")
		and (func.getEntryPoint().(BlockStmt).getStmt(108)=target_10 or func.getEntryPoint().(BlockStmt).getStmt(108).getFollowingStmt()=target_10))
}

predicate func_11(Function func) {
	exists(ExprStmt target_11 |
		target_11.getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("int")
		and target_11.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("NewGUCNestLevel")
		and (func.getEntryPoint().(BlockStmt).getStmt(109)=target_11 or func.getEntryPoint().(BlockStmt).getStmt(109).getFollowingStmt()=target_11))
}

predicate func_12(PointerFieldAccess target_52, Function func) {
	exists(ExprStmt target_12 |
		target_12.getExpr().(FunctionCall).getTarget().hasName("GetUserIdAndSecContext")
		and target_12.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("Oid")
		and target_12.getExpr().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("int")
		and target_12.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(10)=target_12
		and target_12.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_52
		and target_12.getEnclosingFunction() = func)
}

predicate func_13(PointerFieldAccess target_52, Function func) {
	exists(ExprStmt target_13 |
		target_13.getExpr().(FunctionCall).getTarget().hasName("SetUserIdAndSecContext")
		and target_13.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="relowner"
		and target_13.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="rd_rel"
		and target_13.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getType().hasName("Relation")
		and target_13.getExpr().(FunctionCall).getArgument(1).(BitwiseOrExpr).getLeftOperand().(VariableAccess).getType().hasName("int")
		and target_13.getExpr().(FunctionCall).getArgument(1).(BitwiseOrExpr).getRightOperand().(Literal).getValue()="2"
		and target_13.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(11)=target_13
		and target_13.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_52
		and target_13.getEnclosingFunction() = func)
}

predicate func_14(PointerFieldAccess target_52, Function func) {
	exists(ExprStmt target_14 |
		target_14.getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("int")
		and target_14.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("NewGUCNestLevel")
		and target_14.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(12)=target_14
		and target_14.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_52
		and target_14.getEnclosingFunction() = func)
}

predicate func_15(EqualityOperation target_53, Function func) {
	exists(ExprStmt target_15 |
		target_15.getExpr().(FunctionCall).getTarget().hasName("AtEOXact_GUC")
		and target_15.getExpr().(FunctionCall).getArgument(0).(Literal).getValue()="0"
		and target_15.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getType().hasName("int")
		and target_15.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_15
		and target_15.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_53
		and target_15.getEnclosingFunction() = func)
}

predicate func_16(EqualityOperation target_53, Function func) {
	exists(ExprStmt target_16 |
		target_16.getExpr().(FunctionCall).getTarget().hasName("SetUserIdAndSecContext")
		and target_16.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getType().hasName("Oid")
		and target_16.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getType().hasName("int")
		and target_16.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(2)=target_16
		and target_16.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_53
		and target_16.getEnclosingFunction() = func)
}

predicate func_17(PointerFieldAccess target_52, Function func) {
	exists(ExprStmt target_17 |
		target_17.getExpr().(FunctionCall).getTarget().hasName("AtEOXact_GUC")
		and target_17.getExpr().(FunctionCall).getArgument(0).(Literal).getValue()="0"
		and target_17.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getType().hasName("int")
		and target_17.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(18)=target_17
		and target_17.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_52
		and target_17.getEnclosingFunction() = func)
}

predicate func_18(PointerFieldAccess target_52, Function func) {
	exists(ExprStmt target_18 |
		target_18.getExpr().(FunctionCall).getTarget().hasName("SetUserIdAndSecContext")
		and target_18.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getType().hasName("Oid")
		and target_18.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getType().hasName("int")
		and target_18.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(19)=target_18
		and target_18.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_52
		and target_18.getEnclosingFunction() = func)
}

predicate func_19(NotExpr target_54, Function func) {
	exists(ExprStmt target_19 |
		target_19.getExpr() instanceof Literal
		and target_19.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(12)=target_19
		and target_19.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_54
		and target_19.getEnclosingFunction() = func)
}

predicate func_20(NotExpr target_54, Function func) {
	exists(ExprStmt target_20 |
		target_20.getExpr().(FunctionCall).getTarget().hasName("SetUserIdAndSecContext")
		and target_20.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getType().hasName("Oid")
		and target_20.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getType().hasName("int")
		and target_20.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(13)=target_20
		and target_20.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_54
		and target_20.getEnclosingFunction() = func)
}

predicate func_21(NotExpr target_54, Function func) {
	exists(ExprStmt target_21 |
		target_21.getExpr().(FunctionCall).getTarget().hasName("SetUserIdAndSecContext")
		and target_21.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getType().hasName("Oid")
		and target_21.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getType().hasName("int")
		and target_21.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(15)=target_21
		and target_21.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_54
		and target_21.getEnclosingFunction() = func)
}

predicate func_22(VariableAccess target_55, Function func) {
	exists(ExprStmt target_22 |
		target_22.getExpr().(FunctionCall).getTarget().hasName("AtEOXact_GUC")
		and target_22.getExpr().(FunctionCall).getArgument(0).(Literal).getValue()="0"
		and target_22.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getType().hasName("int")
		and target_22.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(3)=target_22
		and target_22.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_55
		and target_22.getEnclosingFunction() = func)
}

predicate func_23(VariableAccess target_55, Function func) {
	exists(ExprStmt target_23 |
		target_23.getExpr().(FunctionCall).getTarget().hasName("SetUserIdAndSecContext")
		and target_23.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getType().hasName("Oid")
		and target_23.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getType().hasName("int")
		and target_23.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(4)=target_23
		and target_23.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_55
		and target_23.getEnclosingFunction() = func)
}

predicate func_24(Function func) {
	exists(ExprStmt target_24 |
		target_24.getExpr().(FunctionCall).getTarget().hasName("AtEOXact_GUC")
		and target_24.getExpr().(FunctionCall).getArgument(0).(Literal).getValue()="0"
		and target_24.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getType().hasName("int")
		and (func.getEntryPoint().(BlockStmt).getStmt(112)=target_24 or func.getEntryPoint().(BlockStmt).getStmt(112).getFollowingStmt()=target_24))
}

predicate func_25(Function func) {
	exists(ExprStmt target_25 |
		target_25.getExpr().(FunctionCall).getTarget().hasName("SetUserIdAndSecContext")
		and target_25.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getType().hasName("Oid")
		and target_25.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getType().hasName("int")
		and (func.getEntryPoint().(BlockStmt).getStmt(113)=target_25 or func.getEntryPoint().(BlockStmt).getStmt(113).getFollowingStmt()=target_25))
}

predicate func_32(Variable vlockmode_548, Variable vchildRelid_1203, Variable vchildrel_1204, ExprStmt target_32) {
		target_32.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vchildrel_1204
		and target_32.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("table_open")
		and target_32.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vchildRelid_1203
		and target_32.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vlockmode_548
}

predicate func_33(Variable vchildrel_1204, Variable vchildidxs_1205, ExprStmt target_33) {
		target_33.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vchildidxs_1205
		and target_33.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("RelationGetIndexList")
		and target_33.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vchildrel_1204
}

predicate func_34(Variable vparentDesc_1180, Variable vchildrel_1204, Variable vattmap_1207, ExprStmt target_34) {
		target_34.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vattmap_1207
		and target_34.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("build_attrmap_by_name")
		and target_34.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="rd_att"
		and target_34.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vchildrel_1204
		and target_34.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vparentDesc_1180
}

predicate func_35(Variable vi_551, ExprStmt target_35) {
		target_35.getExpr().(FunctionCall).getTarget().hasName("pgstat_progress_update_param")
		and target_35.getExpr().(FunctionCall).getArgument(0).(Literal).getValue()="14"
		and target_35.getExpr().(FunctionCall).getArgument(1).(AddExpr).getAnOperand().(VariableAccess).getTarget()=vi_551
		and target_35.getExpr().(FunctionCall).getArgument(1).(AddExpr).getAnOperand().(Literal).getValue()="1"
}

predicate func_36(Variable vattmap_1207, ExprStmt target_36) {
		target_36.getExpr().(FunctionCall).getTarget().hasName("free_attrmap")
		and target_36.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vattmap_1207
}

predicate func_37(PointerFieldAccess target_52, Function func, ExprStmt target_37) {
		target_37.getExpr().(FunctionCall).getTarget().hasName("set_config_option")
		and target_37.getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()="default_tablespace"
		and target_37.getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()=""
		and target_37.getExpr().(FunctionCall).getArgument(5).(Literal).getValue()="1"
		and target_37.getExpr().(FunctionCall).getArgument(6).(Literal).getValue()="0"
		and target_37.getExpr().(FunctionCall).getArgument(7).(Literal).getValue()="0"
		and target_37.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_52
		and target_37.getEnclosingFunction() = func
}

predicate func_38(Parameter vindexRelationId_508, BlockStmt target_56, NotExpr target_38) {
		target_38.getOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vindexRelationId_508
		and target_38.getOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_38.getParent().(IfStmt).getThen()=target_56
}

predicate func_39(Variable vchildidxs_1205, ExprStmt target_39) {
		target_39.getExpr().(FunctionCall).getTarget().hasName("list_free")
		and target_39.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vchildidxs_1205
}

predicate func_40(Variable vchildrel_1204, ExprStmt target_40) {
		target_40.getExpr().(FunctionCall).getTarget().hasName("table_close")
		and target_40.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vchildrel_1204
		and target_40.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
}

predicate func_41(Variable vcollationObjectId_521, Variable vindexInfo_539, Variable vlockmode_548, Variable vopfamOids_1181, Variable vcell_1206, Variable vattmap_1207, Variable vcell__state_1236, Variable vcldidxid_1238, Variable vcldidx_1239, Variable vcldIdxInfo_1240, BlockStmt target_41) {
		target_41.getStmt(0).(ForStmt).getCondition().(ConditionalExpr).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="l"
		and target_41.getStmt(0).(ForStmt).getCondition().(ConditionalExpr).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vcell__state_1236
		and target_41.getStmt(0).(ForStmt).getCondition().(ConditionalExpr).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_41.getStmt(0).(ForStmt).getCondition().(ConditionalExpr).getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getTarget().getName()="i"
		and target_41.getStmt(0).(ForStmt).getCondition().(ConditionalExpr).getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vcell__state_1236
		and target_41.getStmt(0).(ForStmt).getCondition().(ConditionalExpr).getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="length"
		and target_41.getStmt(0).(ForStmt).getCondition().(ConditionalExpr).getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="l"
		and target_41.getStmt(0).(ForStmt).getCondition().(ConditionalExpr).getThen().(CommaExpr).getLeftOperand().(AssignExpr).getLValue().(VariableAccess).getTarget()=vcell_1206
		and target_41.getStmt(0).(ForStmt).getCondition().(ConditionalExpr).getThen().(CommaExpr).getRightOperand().(Literal).getValue()="1"
		and target_41.getStmt(0).(ForStmt).getCondition().(ConditionalExpr).getElse().(CommaExpr).getLeftOperand().(AssignExpr).getLValue().(VariableAccess).getTarget()=vcell_1206
		and target_41.getStmt(0).(ForStmt).getCondition().(ConditionalExpr).getElse().(CommaExpr).getLeftOperand().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_41.getStmt(0).(ForStmt).getCondition().(ConditionalExpr).getElse().(CommaExpr).getRightOperand().(Literal).getValue()="0"
		and target_41.getStmt(0).(ForStmt).getUpdate().(PostfixIncrExpr).getOperand().(ValueFieldAccess).getTarget().getName()="i"
		and target_41.getStmt(0).(ForStmt).getUpdate().(PostfixIncrExpr).getOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vcell__state_1236
		and target_41.getStmt(0).(ForStmt).getStmt().(BlockStmt).getStmt(0).(BlockStmt).getStmt(3).(IfStmt).getCondition().(FunctionCall).getTarget().hasName("has_superclass")
		and target_41.getStmt(0).(ForStmt).getStmt().(BlockStmt).getStmt(0).(BlockStmt).getStmt(3).(IfStmt).getCondition().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vcldidxid_1238
		and target_41.getStmt(0).(ForStmt).getStmt().(BlockStmt).getStmt(0).(BlockStmt).getStmt(4).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vcldidx_1239
		and target_41.getStmt(0).(ForStmt).getStmt().(BlockStmt).getStmt(0).(BlockStmt).getStmt(4).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("index_open")
		and target_41.getStmt(0).(ForStmt).getStmt().(BlockStmt).getStmt(0).(BlockStmt).getStmt(5).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vcldIdxInfo_1240
		and target_41.getStmt(0).(ForStmt).getStmt().(BlockStmt).getStmt(0).(BlockStmt).getStmt(5).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("BuildIndexInfo")
		and target_41.getStmt(0).(ForStmt).getStmt().(BlockStmt).getStmt(0).(BlockStmt).getStmt(6).(IfStmt).getCondition().(FunctionCall).getTarget().hasName("CompareIndexInfo")
		and target_41.getStmt(0).(ForStmt).getStmt().(BlockStmt).getStmt(0).(BlockStmt).getStmt(6).(IfStmt).getCondition().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vcldIdxInfo_1240
		and target_41.getStmt(0).(ForStmt).getStmt().(BlockStmt).getStmt(0).(BlockStmt).getStmt(6).(IfStmt).getCondition().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vindexInfo_539
		and target_41.getStmt(0).(ForStmt).getStmt().(BlockStmt).getStmt(0).(BlockStmt).getStmt(6).(IfStmt).getCondition().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="rd_indcollation"
		and target_41.getStmt(0).(ForStmt).getStmt().(BlockStmt).getStmt(0).(BlockStmt).getStmt(6).(IfStmt).getCondition().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vcollationObjectId_521
		and target_41.getStmt(0).(ForStmt).getStmt().(BlockStmt).getStmt(0).(BlockStmt).getStmt(6).(IfStmt).getCondition().(FunctionCall).getArgument(4).(PointerFieldAccess).getTarget().getName()="rd_opfamily"
		and target_41.getStmt(0).(ForStmt).getStmt().(BlockStmt).getStmt(0).(BlockStmt).getStmt(6).(IfStmt).getCondition().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vopfamOids_1181
		and target_41.getStmt(0).(ForStmt).getStmt().(BlockStmt).getStmt(0).(BlockStmt).getStmt(6).(IfStmt).getCondition().(FunctionCall).getArgument(6).(VariableAccess).getTarget()=vattmap_1207
		and target_41.getStmt(0).(ForStmt).getStmt().(BlockStmt).getStmt(0).(BlockStmt).getStmt(7).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("index_close")
		and target_41.getStmt(0).(ForStmt).getStmt().(BlockStmt).getStmt(0).(BlockStmt).getStmt(7).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vcldidx_1239
		and target_41.getStmt(0).(ForStmt).getStmt().(BlockStmt).getStmt(0).(BlockStmt).getStmt(7).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vlockmode_548
}

predicate func_44(Function func, Initializer target_44) {
		target_44.getExpr().(UnaryMinusExpr).getValue()="-1"
		and target_44.getExpr().getEnclosingFunction() = func
}

predicate func_45(Function func, FunctionCall target_45) {
		target_45.getTarget().hasName("GetUserId")
		and target_45.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("pg_namespace_aclcheck")
		and target_45.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("Oid")
		and target_45.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(BinaryBitwiseOperation).getValue()="512"
		and target_45.getEnclosingFunction() = func
}

predicate func_46(Function func, FunctionCall target_46) {
		target_46.getTarget().hasName("GetUserId")
		and target_46.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("pg_tablespace_aclcheck")
		and target_46.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("Oid")
		and target_46.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(BinaryBitwiseOperation).getValue()="512"
		and target_46.getEnclosingFunction() = func
}

predicate func_47(Variable vsave_nestlevel_550, RelationalOperation target_47) {
		 (target_47 instanceof GEExpr or target_47 instanceof LEExpr)
		and target_47.getGreaterOperand().(VariableAccess).getTarget()=vsave_nestlevel_550
		and target_47.getLesserOperand() instanceof Literal
		and target_47.getParent().(IfStmt).getThen().(ExprStmt).getExpr() instanceof FunctionCall
}

predicate func_48(Parameter vparentIndexId_509, Variable vrel_529, Variable vaddress_545, Function func, IfStmt target_48) {
		target_48.getCondition() instanceof NotExpr
		and target_48.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("table_close")
		and target_48.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vrel_529
		and target_48.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_48.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vparentIndexId_509
		and target_48.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_48.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("pgstat_progress_end_command")
		and target_48.getThen().(BlockStmt).getStmt(2).(ReturnStmt).getExpr().(VariableAccess).getTarget()=vaddress_545
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_48
}

predicate func_49(Variable vsave_nestlevel_550, ExprStmt target_49) {
		target_49.getExpr().(FunctionCall).getTarget().hasName("AtEOXact_GUC")
		and target_49.getExpr().(FunctionCall).getArgument(0) instanceof Literal
		and target_49.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vsave_nestlevel_550
}

predicate func_50(Variable vrel_529, ExprStmt target_50) {
		target_50.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("Oid")
		and target_50.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="relnamespace"
		and target_50.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="rd_rel"
		and target_50.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrel_529
}

predicate func_51(Variable vrel_529, PointerFieldAccess target_51) {
		target_51.getTarget().getName()="relkind"
		and target_51.getQualifier().(PointerFieldAccess).getTarget().getName()="rd_rel"
		and target_51.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrel_529
}

predicate func_52(PointerFieldAccess target_52) {
		target_52.getTarget().getName()="reset_default_tblspc"
		and target_52.getQualifier().(VariableAccess).getTarget().getType().hasName("IndexStmt *")
}

predicate func_53(Variable vchildrel_1204, EqualityOperation target_53) {
		target_53.getAnOperand().(PointerFieldAccess).getTarget().getName()="relkind"
		and target_53.getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="rd_rel"
		and target_53.getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vchildrel_1204
		and target_53.getAnOperand().(Literal).getValue()="102"
}

predicate func_54(NotExpr target_54) {
		target_54.getOperand().(VariableAccess).getTarget().getType().hasName("bool")
}

predicate func_55(Variable vpartitioned_535, VariableAccess target_55) {
		target_55.getTarget()=vpartitioned_535
}

predicate func_56(Parameter vparentIndexId_509, Variable vrel_529, BlockStmt target_56) {
		target_56.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("table_close")
		and target_56.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vrel_529
		and target_56.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_56.getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vparentIndexId_509
		and target_56.getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_56.getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("pgstat_progress_end_command")
}

from Function func, Parameter vindexRelationId_508, Parameter vparentIndexId_509, Variable vcollationObjectId_521, Variable vrel_529, Variable vpartitioned_535, Variable vindexInfo_539, Variable vaddress_545, Variable vlockmode_548, Variable vsave_nestlevel_550, Variable vi_551, Variable vparentDesc_1180, Variable vopfamOids_1181, Variable vchildRelid_1203, Variable vchildrel_1204, Variable vchildidxs_1205, Variable vcell_1206, Variable vattmap_1207, Variable vcell__state_1236, Variable vcldidxid_1238, Variable vcldidx_1239, Variable vcldIdxInfo_1240, VariableAccess target_0, Literal target_1, VariableAccess target_3, ExprStmt target_32, ExprStmt target_33, ExprStmt target_34, ExprStmt target_35, ExprStmt target_36, ExprStmt target_37, NotExpr target_38, ExprStmt target_39, ExprStmt target_40, BlockStmt target_41, Initializer target_44, FunctionCall target_45, FunctionCall target_46, RelationalOperation target_47, IfStmt target_48, ExprStmt target_49, ExprStmt target_50, PointerFieldAccess target_51, PointerFieldAccess target_52, EqualityOperation target_53, NotExpr target_54, VariableAccess target_55, BlockStmt target_56
where
func_0(vsave_nestlevel_550, target_0)
and func_1(vsave_nestlevel_550, target_47, target_1)
and func_3(vsave_nestlevel_550, target_49, target_3)
and not func_5(func)
and not func_6(vrel_529, target_50, target_51, func)
and not func_9(target_38, func)
and not func_10(func)
and not func_11(func)
and not func_12(target_52, func)
and not func_13(target_52, func)
and not func_14(target_52, func)
and not func_15(target_53, func)
and not func_16(target_53, func)
and not func_17(target_52, func)
and not func_18(target_52, func)
and not func_19(target_54, func)
and not func_20(target_54, func)
and not func_21(target_54, func)
and not func_22(target_55, func)
and not func_23(target_55, func)
and not func_24(func)
and not func_25(func)
and func_32(vlockmode_548, vchildRelid_1203, vchildrel_1204, target_32)
and func_33(vchildrel_1204, vchildidxs_1205, target_33)
and func_34(vparentDesc_1180, vchildrel_1204, vattmap_1207, target_34)
and func_35(vi_551, target_35)
and func_36(vattmap_1207, target_36)
and func_37(target_52, func, target_37)
and func_38(vindexRelationId_508, target_56, target_38)
and func_39(vchildidxs_1205, target_39)
and func_40(vchildrel_1204, target_40)
and func_41(vcollationObjectId_521, vindexInfo_539, vlockmode_548, vopfamOids_1181, vcell_1206, vattmap_1207, vcell__state_1236, vcldidxid_1238, vcldidx_1239, vcldIdxInfo_1240, target_41)
and func_44(func, target_44)
and func_45(func, target_45)
and func_46(func, target_46)
and func_47(vsave_nestlevel_550, target_47)
and func_48(vparentIndexId_509, vrel_529, vaddress_545, func, target_48)
and func_49(vsave_nestlevel_550, target_49)
and func_50(vrel_529, target_50)
and func_51(vrel_529, target_51)
and func_52(target_52)
and func_53(vchildrel_1204, target_53)
and func_54(target_54)
and func_55(vpartitioned_535, target_55)
and func_56(vparentIndexId_509, vrel_529, target_56)
and vindexRelationId_508.getType().hasName("Oid")
and vparentIndexId_509.getType().hasName("Oid")
and vcollationObjectId_521.getType().hasName("Oid *")
and vrel_529.getType().hasName("Relation")
and vpartitioned_535.getType().hasName("bool")
and vindexInfo_539.getType().hasName("IndexInfo *")
and vaddress_545.getType().hasName("ObjectAddress")
and vlockmode_548.getType().hasName("LOCKMODE")
and vsave_nestlevel_550.getType().hasName("int")
and vi_551.getType().hasName("int")
and vparentDesc_1180.getType().hasName("TupleDesc")
and vopfamOids_1181.getType().hasName("Oid *")
and vchildRelid_1203.getType().hasName("Oid")
and vchildrel_1204.getType().hasName("Relation")
and vchildidxs_1205.getType().hasName("List *")
and vcell_1206.getType().hasName("ListCell *")
and vattmap_1207.getType().hasName("AttrMap *")
and vcell__state_1236.getType().hasName("ForEachState")
and vcldidxid_1238.getType().hasName("Oid")
and vcldidx_1239.getType().hasName("Relation")
and vcldIdxInfo_1240.getType().hasName("IndexInfo *")
and vindexRelationId_508.getFunction() = func
and vparentIndexId_509.getFunction() = func
and vcollationObjectId_521.(LocalVariable).getFunction() = func
and vrel_529.(LocalVariable).getFunction() = func
and vpartitioned_535.(LocalVariable).getFunction() = func
and vindexInfo_539.(LocalVariable).getFunction() = func
and vaddress_545.(LocalVariable).getFunction() = func
and vlockmode_548.(LocalVariable).getFunction() = func
and vsave_nestlevel_550.(LocalVariable).getFunction() = func
and vi_551.(LocalVariable).getFunction() = func
and vparentDesc_1180.(LocalVariable).getFunction() = func
and vopfamOids_1181.(LocalVariable).getFunction() = func
and vchildRelid_1203.(LocalVariable).getFunction() = func
and vchildrel_1204.(LocalVariable).getFunction() = func
and vchildidxs_1205.(LocalVariable).getFunction() = func
and vcell_1206.(LocalVariable).getFunction() = func
and vattmap_1207.(LocalVariable).getFunction() = func
and vcell__state_1236.(LocalVariable).getFunction() = func
and vcldidxid_1238.(LocalVariable).getFunction() = func
and vcldidx_1239.(LocalVariable).getFunction() = func
and vcldIdxInfo_1240.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
