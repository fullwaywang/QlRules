/**
 * @name redis-f6a40570fa63d5afdd596c78083d754081d80ae3-zsetAdd
 * @id cpp/redis/f6a40570fa63d5afdd596c78083d754081d80ae3/zsetAdd
 * @description redis-f6a40570fa63d5afdd596c78083d754081d80ae3-src/t_zset.c-zsetAdd CVE-2021-32627
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vserver, ExprStmt target_9, LogicalOrExpr target_10) {
	exists(LogicalOrExpr target_0 |
		target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand() instanceof FunctionCall
		and target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(Literal).getValue()="1"
		and target_0.getAnOperand().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getTarget().getName()="zset_max_ziplist_entries"
		and target_0.getAnOperand().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vserver
		and target_0.getAnOperand() instanceof RelationalOperation
		and target_0.getParent().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand() instanceof FunctionCall
		and target_0.getParent().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getTarget().getName()="zset_max_ziplist_entries"
		and target_0.getParent().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vserver
		and target_0.getParent().(LogicalOrExpr).getAnOperand() instanceof RelationalOperation
		and target_0.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen()=target_9
		and target_0.getAnOperand().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_10.getAnOperand().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

/*predicate func_1(Function func) {
	exists(AddExpr target_1 |
		target_1.getAnOperand() instanceof FunctionCall
		and target_1.getAnOperand().(Literal).getValue()="1"
		and target_1.getEnclosingFunction() = func)
}

*/
predicate func_2(Parameter vele_1315, Variable vserver, Parameter vzobj_1315, ExprStmt target_9, ExprStmt target_6, LogicalOrExpr target_10) {
	exists(NotExpr target_2 |
		target_2.getOperand().(FunctionCall).getTarget().hasName("ziplistSafeToAdd")
		and target_2.getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="ptr"
		and target_2.getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vzobj_1315
		and target_2.getOperand().(FunctionCall).getArgument(1).(FunctionCall).getTarget().hasName("sdslen")
		and target_2.getOperand().(FunctionCall).getArgument(1).(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vele_1315
		and target_2.getParent().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand() instanceof FunctionCall
		and target_2.getParent().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getTarget().getName()="zset_max_ziplist_entries"
		and target_2.getParent().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vserver
		and target_2.getParent().(LogicalOrExpr).getAnOperand() instanceof RelationalOperation
		and target_2.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen()=target_9
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_2.getOperand().(FunctionCall).getArgument(1).(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_3(Parameter vscore_1315, Parameter vnewscore_1315, NotExpr target_11, IfStmt target_3) {
		target_3.getCondition().(VariableAccess).getTarget()=vnewscore_1315
		and target_3.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vnewscore_1315
		and target_3.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vscore_1315
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_11
}

predicate func_4(Parameter vflags_1315, NotExpr target_11, ExprStmt target_4) {
		target_4.getExpr().(AssignOrExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vflags_1315
		and target_4.getExpr().(AssignOrExpr).getRValue().(BinaryBitwiseOperation).getValue()="32"
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_11
}

predicate func_5(NotExpr target_11, Function func, ReturnStmt target_5) {
		target_5.getExpr().(Literal).getValue()="1"
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_11
		and target_5.getEnclosingFunction() = func
}

predicate func_6(Parameter vscore_1315, Parameter vele_1315, Parameter vzobj_1315, NotExpr target_11, ExprStmt target_6) {
		target_6.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="ptr"
		and target_6.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vzobj_1315
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("zzlInsert")
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="ptr"
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vzobj_1315
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vele_1315
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vscore_1315
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_11
}

/*predicate func_7(Parameter vzobj_1315, FunctionCall target_7) {
		target_7.getTarget().hasName("zzlLength")
		and target_7.getArgument(0).(PointerFieldAccess).getTarget().getName()="ptr"
		and target_7.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vzobj_1315
}

*/
predicate func_8(Parameter vele_1315, Variable vserver, Parameter vzobj_1315, ExprStmt target_9, RelationalOperation target_8) {
		 (target_8 instanceof GTExpr or target_8 instanceof LTExpr)
		and target_8.getGreaterOperand().(FunctionCall).getTarget().hasName("sdslen")
		and target_8.getGreaterOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vele_1315
		and target_8.getLesserOperand().(ValueFieldAccess).getTarget().getName()="zset_max_ziplist_value"
		and target_8.getLesserOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vserver
		and target_8.getParent().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(FunctionCall).getTarget().hasName("zzlLength")
		and target_8.getParent().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="ptr"
		and target_8.getParent().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vzobj_1315
		and target_8.getParent().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getTarget().getName()="zset_max_ziplist_entries"
		and target_8.getParent().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vserver
		and target_8.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen()=target_9
}

predicate func_9(Parameter vzobj_1315, LogicalOrExpr target_10, ExprStmt target_9) {
		target_9.getExpr().(FunctionCall).getTarget().hasName("zsetConvert")
		and target_9.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vzobj_1315
		and target_9.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="7"
		and target_9.getParent().(IfStmt).getCondition()=target_10
}

predicate func_10(Variable vserver, LogicalOrExpr target_10) {
		target_10.getAnOperand().(RelationalOperation).getGreaterOperand() instanceof FunctionCall
		and target_10.getAnOperand().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getTarget().getName()="zset_max_ziplist_entries"
		and target_10.getAnOperand().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vserver
		and target_10.getAnOperand() instanceof RelationalOperation
}

predicate func_11(NotExpr target_11) {
		target_11.getOperand().(VariableAccess).getTarget().getType().hasName("int")
}

from Function func, Parameter vscore_1315, Parameter vele_1315, Parameter vflags_1315, Parameter vnewscore_1315, Variable vserver, Parameter vzobj_1315, IfStmt target_3, ExprStmt target_4, ReturnStmt target_5, ExprStmt target_6, RelationalOperation target_8, ExprStmt target_9, LogicalOrExpr target_10, NotExpr target_11
where
not func_0(vserver, target_9, target_10)
and not func_2(vele_1315, vserver, vzobj_1315, target_9, target_6, target_10)
and func_3(vscore_1315, vnewscore_1315, target_11, target_3)
and func_4(vflags_1315, target_11, target_4)
and func_5(target_11, func, target_5)
and func_6(vscore_1315, vele_1315, vzobj_1315, target_11, target_6)
and func_8(vele_1315, vserver, vzobj_1315, target_9, target_8)
and func_9(vzobj_1315, target_10, target_9)
and func_10(vserver, target_10)
and func_11(target_11)
and vscore_1315.getType().hasName("double")
and vele_1315.getType().hasName("sds")
and vflags_1315.getType().hasName("int *")
and vnewscore_1315.getType().hasName("double *")
and vserver.getType().hasName("redisServer")
and vzobj_1315.getType().hasName("robj *")
and vscore_1315.getFunction() = func
and vele_1315.getFunction() = func
and vflags_1315.getFunction() = func
and vnewscore_1315.getFunction() = func
and not vserver.getParentScope+() = func
and vzobj_1315.getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
