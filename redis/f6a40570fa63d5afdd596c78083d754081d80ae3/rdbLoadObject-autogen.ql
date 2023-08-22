/**
 * @name redis-f6a40570fa63d5afdd596c78083d754081d80ae3-rdbLoadObject
 * @id cpp/redis/f6a40570fa63d5afdd596c78083d754081d80ae3/rdbLoadObject
 * @description redis-f6a40570fa63d5afdd596c78083d754081d80ae3-src/rdb.c-rdbLoadObject CVE-2021-32627
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vfield_1613, FunctionCall target_0) {
		target_0.getTarget().hasName("sdsfree")
		and not target_0.getTarget().hasName("rdbReportError")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vfield_1613
}

predicate func_1(Variable vvalue_1613, FunctionCall target_1) {
		target_1.getTarget().hasName("sdsfree")
		and not target_1.getTarget().hasName("rdbReportError")
		and target_1.getArgument(0).(VariableAccess).getTarget()=vvalue_1613
}

predicate func_3(Function func) {
	exists(AssignAddExpr target_3 |
		target_3.getLValue().(VariableAccess).getType().hasName("size_t")
		and target_3.getRValue().(FunctionCall).getTarget().hasName("sdslen")
		and target_3.getRValue().(FunctionCall).getArgument(0).(VariableAccess).getType().hasName("sds")
		and target_3.getEnclosingFunction() = func)
}

predicate func_4(ExprStmt target_15, Function func) {
	exists(LogicalAndExpr target_4 |
		target_4.getAnOperand() instanceof LogicalAndExpr
		and target_4.getAnOperand().(FunctionCall).getTarget().hasName("ziplistSafeToAdd")
		and target_4.getAnOperand().(FunctionCall).getArgument(0).(Literal).getValue()="0"
		and target_4.getAnOperand().(FunctionCall).getArgument(1).(VariableAccess).getType().hasName("size_t")
		and target_4.getParent().(IfStmt).getThen()=target_15
		and target_4.getEnclosingFunction() = func)
}

predicate func_5(Variable vo_1488, Variable vfield_1613, Variable vvalue_1613, BlockStmt target_21, ExprStmt target_22, ExprStmt target_17, ExprStmt target_12) {
	exists(LogicalOrExpr target_5 |
		target_5.getAnOperand() instanceof LogicalOrExpr
		and target_5.getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("ziplistSafeToAdd")
		and target_5.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="ptr"
		and target_5.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vo_1488
		and target_5.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(AddExpr).getAnOperand().(FunctionCall).getTarget().hasName("sdslen")
		and target_5.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(AddExpr).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vfield_1613
		and target_5.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(AddExpr).getAnOperand().(FunctionCall).getTarget().hasName("sdslen")
		and target_5.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(AddExpr).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vvalue_1613
		and target_5.getParent().(IfStmt).getThen()=target_21
		and target_22.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_5.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_5.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_17.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_12.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_5.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(AddExpr).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_6(Variable vo_1488, Variable vret_1612, Variable vfield_1613, Variable vvalue_1613, ExprStmt target_17, LogicalAndExpr target_23, ExprStmt target_13) {
	exists(AssignExpr target_6 |
		target_6.getLValue().(VariableAccess).getTarget()=vret_1612
		and target_6.getRValue().(FunctionCall).getTarget().hasName("dictAdd")
		and target_6.getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="ptr"
		and target_6.getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vo_1488
		and target_6.getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vfield_1613
		and target_6.getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vvalue_1613
		and target_17.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_6.getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_6.getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_23.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_13.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_6.getRValue().(FunctionCall).getArgument(2).(VariableAccess).getLocation()))
}

predicate func_7(Variable vret_1612, LogicalOrExpr target_16) {
	exists(IfStmt target_7 |
		target_7.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vret_1612
		and target_7.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="1"
		and target_7.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("rdbReportError")
		and target_7.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0) instanceof Literal
		and target_7.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof Literal
		and target_7.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Duplicate hash fields detected"
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(2)=target_7
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_16)
}

predicate func_9(Variable vzl_1720, Variable vflen_1723, Variable vvlen_1723, ExprStmt target_26, ExprStmt target_27, ExprStmt target_28, ExprStmt target_29) {
	exists(IfStmt target_9 |
		target_9.getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("ziplistSafeToAdd")
		and target_9.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vzl_1720
		and target_9.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(AddExpr).getAnOperand().(VariableAccess).getTarget()=vflen_1723
		and target_9.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(AddExpr).getAnOperand().(VariableAccess).getTarget()=vvlen_1723
		and target_9.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("rdbReportError")
		and target_9.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0) instanceof Literal
		and target_9.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof Literal
		and target_9.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Hash zipmap too big (%u)"
		and target_9.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getType().hasName("unsigned int")
		and target_26.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation().isBefore(target_9.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(AddExpr).getAnOperand().(VariableAccess).getLocation())
		and target_9.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(AddExpr).getAnOperand().(VariableAccess).getLocation().isBefore(target_27.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getLocation())
		and target_28.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation().isBefore(target_9.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(AddExpr).getAnOperand().(VariableAccess).getLocation())
		and target_9.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(AddExpr).getAnOperand().(VariableAccess).getLocation().isBefore(target_29.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getLocation()))
}

predicate func_12(Variable vfield_1613, LogicalOrExpr target_16, ExprStmt target_12) {
		target_12.getExpr().(FunctionCall).getTarget().hasName("sdsfree")
		and target_12.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vfield_1613
		and target_12.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_16
}

predicate func_13(Variable vvalue_1613, LogicalOrExpr target_16, ExprStmt target_13) {
		target_13.getExpr().(FunctionCall).getTarget().hasName("sdsfree")
		and target_13.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vvalue_1613
		and target_13.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_16
}

predicate func_14(Variable vo_1488, Variable vserver, Variable vmaxelelen_1564, ExprStmt target_15, LogicalAndExpr target_14) {
		target_14.getAnOperand().(RelationalOperation).getLesserOperand().(FunctionCall).getTarget().hasName("zsetLength")
		and target_14.getAnOperand().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vo_1488
		and target_14.getAnOperand().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getTarget().getName()="zset_max_ziplist_entries"
		and target_14.getAnOperand().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vserver
		and target_14.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vmaxelelen_1564
		and target_14.getAnOperand().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getTarget().getName()="zset_max_ziplist_value"
		and target_14.getAnOperand().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vserver
		and target_14.getParent().(IfStmt).getThen()=target_15
}

predicate func_15(Variable vo_1488, LogicalAndExpr target_14, ExprStmt target_15) {
		target_15.getExpr().(FunctionCall).getTarget().hasName("zsetConvert")
		and target_15.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vo_1488
		and target_15.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="5"
		and target_15.getParent().(IfStmt).getCondition()=target_14
}

predicate func_16(Variable vserver, Variable vfield_1613, Variable vvalue_1613, BlockStmt target_21, LogicalOrExpr target_16) {
		target_16.getAnOperand().(RelationalOperation).getGreaterOperand().(FunctionCall).getTarget().hasName("sdslen")
		and target_16.getAnOperand().(RelationalOperation).getGreaterOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vfield_1613
		and target_16.getAnOperand().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getTarget().getName()="hash_max_ziplist_value"
		and target_16.getAnOperand().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vserver
		and target_16.getAnOperand().(RelationalOperation).getGreaterOperand().(FunctionCall).getTarget().hasName("sdslen")
		and target_16.getAnOperand().(RelationalOperation).getGreaterOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vvalue_1613
		and target_16.getAnOperand().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getTarget().getName()="hash_max_ziplist_value"
		and target_16.getAnOperand().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vserver
		and target_16.getParent().(IfStmt).getThen()=target_21
}

predicate func_17(Variable vo_1488, LogicalOrExpr target_16, ExprStmt target_17) {
		target_17.getExpr().(FunctionCall).getTarget().hasName("hashTypeConvert")
		and target_17.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vo_1488
		and target_17.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="2"
		and target_17.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_16
}

predicate func_18(LogicalOrExpr target_16, Function func, BreakStmt target_18) {
		target_18.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_16
		and target_18.getEnclosingFunction() = func
}

predicate func_19(Variable vfield_1613, VariableAccess target_19) {
		target_19.getTarget()=vfield_1613
		and target_19.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall
}

predicate func_20(Variable vvalue_1613, VariableAccess target_20) {
		target_20.getTarget()=vvalue_1613
		and target_20.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall
}

predicate func_21(BlockStmt target_21) {
		target_21.getStmt(0) instanceof ExprStmt
		and target_21.getStmt(1) instanceof ExprStmt
		and target_21.getStmt(2) instanceof ExprStmt
		and target_21.getStmt(3) instanceof BreakStmt
}

predicate func_22(Variable vo_1488, Variable vvalue_1613, ExprStmt target_22) {
		target_22.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="ptr"
		and target_22.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vo_1488
		and target_22.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ziplistPush")
		and target_22.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="ptr"
		and target_22.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vo_1488
		and target_22.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vvalue_1613
		and target_22.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(FunctionCall).getTarget().hasName("sdslen")
		and target_22.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vvalue_1613
		and target_22.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(Literal).getValue()="1"
}

predicate func_23(Variable vo_1488, LogicalAndExpr target_23) {
		target_23.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="encoding"
		and target_23.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vo_1488
		and target_23.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="2"
		and target_23.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget().getType().hasName("uint64_t")
		and target_23.getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="4"
}

predicate func_26(Variable vflen_1723, ExprStmt target_26) {
		target_26.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("unsigned int")
		and target_26.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vflen_1723
}

predicate func_27(Variable vzl_1720, Variable vflen_1723, ExprStmt target_27) {
		target_27.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vzl_1720
		and target_27.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ziplistPush")
		and target_27.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vzl_1720
		and target_27.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget().getType().hasName("unsigned char *")
		and target_27.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vflen_1723
		and target_27.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(Literal).getValue()="1"
}

predicate func_28(Variable vvlen_1723, ExprStmt target_28) {
		target_28.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("unsigned int")
		and target_28.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vvlen_1723
}

predicate func_29(Variable vzl_1720, Variable vvlen_1723, ExprStmt target_29) {
		target_29.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vzl_1720
		and target_29.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ziplistPush")
		and target_29.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vzl_1720
		and target_29.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget().getType().hasName("unsigned char *")
		and target_29.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vvlen_1723
		and target_29.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(Literal).getValue()="1"
}

from Function func, Variable vo_1488, Variable vserver, Variable vmaxelelen_1564, Variable vret_1612, Variable vfield_1613, Variable vvalue_1613, Variable vzl_1720, Variable vflen_1723, Variable vvlen_1723, FunctionCall target_0, FunctionCall target_1, ExprStmt target_12, ExprStmt target_13, LogicalAndExpr target_14, ExprStmt target_15, LogicalOrExpr target_16, ExprStmt target_17, BreakStmt target_18, VariableAccess target_19, VariableAccess target_20, BlockStmt target_21, ExprStmt target_22, LogicalAndExpr target_23, ExprStmt target_26, ExprStmt target_27, ExprStmt target_28, ExprStmt target_29
where
func_0(vfield_1613, target_0)
and func_1(vvalue_1613, target_1)
and not func_3(func)
and not func_4(target_15, func)
and not func_5(vo_1488, vfield_1613, vvalue_1613, target_21, target_22, target_17, target_12)
and not func_6(vo_1488, vret_1612, vfield_1613, vvalue_1613, target_17, target_23, target_13)
and not func_7(vret_1612, target_16)
and not func_9(vzl_1720, vflen_1723, vvlen_1723, target_26, target_27, target_28, target_29)
and func_12(vfield_1613, target_16, target_12)
and func_13(vvalue_1613, target_16, target_13)
and func_14(vo_1488, vserver, vmaxelelen_1564, target_15, target_14)
and func_15(vo_1488, target_14, target_15)
and func_16(vserver, vfield_1613, vvalue_1613, target_21, target_16)
and func_17(vo_1488, target_16, target_17)
and func_18(target_16, func, target_18)
and func_19(vfield_1613, target_19)
and func_20(vvalue_1613, target_20)
and func_21(target_21)
and func_22(vo_1488, vvalue_1613, target_22)
and func_23(vo_1488, target_23)
and func_26(vflen_1723, target_26)
and func_27(vzl_1720, vflen_1723, target_27)
and func_28(vvlen_1723, target_28)
and func_29(vzl_1720, vvlen_1723, target_29)
and vo_1488.getType().hasName("robj *")
and vserver.getType().hasName("redisServer")
and vmaxelelen_1564.getType().hasName("size_t")
and vret_1612.getType().hasName("int")
and vfield_1613.getType().hasName("sds")
and vvalue_1613.getType().hasName("sds")
and vzl_1720.getType().hasName("unsigned char *")
and vflen_1723.getType().hasName("unsigned int")
and vvlen_1723.getType().hasName("unsigned int")
and vo_1488.(LocalVariable).getFunction() = func
and not vserver.getParentScope+() = func
and vmaxelelen_1564.(LocalVariable).getFunction() = func
and vret_1612.(LocalVariable).getFunction() = func
and vfield_1613.(LocalVariable).getFunction() = func
and vvalue_1613.(LocalVariable).getFunction() = func
and vzl_1720.(LocalVariable).getFunction() = func
and vflen_1723.(LocalVariable).getFunction() = func
and vvlen_1723.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
