/**
 * @name postgresql-a5fa3e0671474411ad81600a8f2b4800a4464afc-adjust_partition_tlist
 * @id cpp/postgresql/a5fa3e0671474411ad81600a8f2b4800a4464afc/adjust-partition-tlist
 * @description postgresql-a5fa3e0671474411ad81600a8f2b4800a4464afc-src/backend/executor/execPartition.c-adjust_partition_tlist CVE-2021-32028
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vtlist_1515, Variable vattrno_1520, VariableAccess target_0) {
		target_0.getTarget()=vattrno_1520
		and target_0.getParent().(SubExpr).getParent().(ArrayExpr).getParent().(SubExpr).getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("list_nth")
		and target_0.getParent().(SubExpr).getParent().(ArrayExpr).getParent().(SubExpr).getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtlist_1515
		and target_0.getParent().(SubExpr).getParent().(ArrayExpr).getParent().(SubExpr).getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1) instanceof SubExpr
}

predicate func_1(Variable vnew_tlist_1517, Variable vattrno_1520, Variable vtle_1525, Variable vexpr_1540, ReturnStmt target_15, SubExpr target_14, ExprStmt target_16, Function func) {
	exists(ForStmt target_1 |
		target_1.getInitialization() instanceof ExprStmt
		and target_1.getCondition() instanceof RelationalOperation
		and target_1.getUpdate() instanceof PostfixIncrExpr
		and target_1.getStmt().(BlockStmt).getStmt(3).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getType().hasName("AttrNumber")
		and target_1.getStmt().(BlockStmt).getStmt(3).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_1.getStmt().(BlockStmt).getStmt(3).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(Literal).getValue()="1"
		and target_1.getStmt().(BlockStmt).getStmt(3).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vtle_1525
		and target_1.getStmt().(BlockStmt).getStmt(3).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("list_nth")
		and target_1.getStmt().(BlockStmt).getStmt(3).(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(Literal).getValue()="1"
		and target_1.getStmt().(BlockStmt).getStmt(3).(IfStmt).getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(Literal).getValue()="1"
		and target_1.getStmt().(BlockStmt).getStmt(3).(IfStmt).getThen().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="resno"
		and target_1.getStmt().(BlockStmt).getStmt(3).(IfStmt).getThen().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vattrno_1520
		and target_1.getStmt().(BlockStmt).getStmt(3).(IfStmt).getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(Literal).getValue()="1"
		and target_1.getStmt().(BlockStmt).getStmt(3).(IfStmt).getElse().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vexpr_1540
		and target_1.getStmt().(BlockStmt).getStmt(3).(IfStmt).getElse().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("makeConst")
		and target_1.getStmt().(BlockStmt).getStmt(3).(IfStmt).getElse().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vtle_1525
		and target_1.getStmt().(BlockStmt).getStmt(3).(IfStmt).getElse().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("makeTargetEntry")
		and target_1.getStmt().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vnew_tlist_1517
		and target_1.getStmt().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("lappend")
		and target_1.getStmt().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vnew_tlist_1517
		and target_1.getStmt().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vtle_1525
		and (func.getEntryPoint().(BlockStmt).getStmt(5)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(5).getFollowingStmt()=target_1)
		and target_1.getStmt().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_15.getExpr().(VariableAccess).getLocation())
		and target_14.getLeftOperand().(ArrayExpr).getArrayOffset().(SubExpr).getLeftOperand().(VariableAccess).getLocation().isBefore(target_1.getStmt().(BlockStmt).getStmt(3).(IfStmt).getThen().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation())
		and target_1.getStmt().(BlockStmt).getStmt(3).(IfStmt).getThen().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation().isBefore(target_16.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getLocation()))
}

/*predicate func_3(EqualityOperation target_17, Function func) {
	exists(ExprStmt target_3 |
		target_3.getExpr().(Literal).getValue()="1"
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(2)=target_3
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_17
		and target_3.getEnclosingFunction() = func)
}

*/
/*predicate func_4(EqualityOperation target_17, Function func) {
	exists(ExprStmt target_4 |
		target_4.getExpr().(Literal).getValue()="1"
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(3)=target_4
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_17
		and target_4.getEnclosingFunction() = func)
}

*/
predicate func_5(Parameter vtlist_1515, ExprStmt target_18) {
	exists(ExprStmt target_5 |
		target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("ListCell *")
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("list_head")
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtlist_1515
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_18.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_6(BlockStmt target_19, Function func) {
	exists(EqualityOperation target_6 |
		target_6.getAnOperand().(VariableAccess).getType().hasName("ListCell *")
		and target_6.getAnOperand().(Literal).getValue()="0"
		and target_6.getParent().(ForStmt).getStmt()=target_19
		and target_6.getEnclosingFunction() = func)
}

predicate func_7(Function func) {
	exists(AssignExpr target_7 |
		target_7.getLValue().(VariableAccess).getType().hasName("ListCell *")
		and target_7.getRValue().(PointerFieldAccess).getTarget().getName()="next"
		and target_7.getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getType().hasName("ListCell *")
		and target_7.getEnclosingFunction() = func)
}

predicate func_8(Variable vnew_tlist_1517) {
	exists(IfStmt target_8 |
		target_8.getCondition().(PointerFieldAccess).getTarget().getName()="resjunk"
		and target_8.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getType().hasName("TargetEntry *")
		and target_8.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="resno"
		and target_8.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getType().hasName("TargetEntry *")
		and target_8.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(FunctionCall).getTarget().hasName("list_length")
		and target_8.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vnew_tlist_1517
		and target_8.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand() instanceof Literal
		and target_8.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vnew_tlist_1517
		and target_8.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("lappend")
		and target_8.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vnew_tlist_1517
		and target_8.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getType().hasName("TargetEntry *"))
}

predicate func_9(Variable vattrno_1520, ExprStmt target_9) {
		target_9.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vattrno_1520
		and target_9.getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
}

predicate func_10(Variable vtupdesc_1518, Variable vattrno_1520, BlockStmt target_19, RelationalOperation target_10) {
		 (target_10 instanceof GEExpr or target_10 instanceof LEExpr)
		and target_10.getLesserOperand().(VariableAccess).getTarget()=vattrno_1520
		and target_10.getGreaterOperand().(PointerFieldAccess).getTarget().getName()="natts"
		and target_10.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtupdesc_1518
		and target_10.getParent().(ForStmt).getStmt()=target_19
}

predicate func_11(Variable vattrno_1520, PostfixIncrExpr target_11) {
		target_11.getOperand().(VariableAccess).getTarget()=vattrno_1520
}

predicate func_12(Variable vattrMap_1519, Variable vattrno_1520, BlockStmt target_20, ArrayExpr target_12) {
		target_12.getArrayBase().(VariableAccess).getTarget()=vattrMap_1519
		and target_12.getArrayOffset().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vattrno_1520
		and target_12.getArrayOffset().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_12.getParent().(NEExpr).getAnOperand().(Literal).getValue()="0"
		and target_12.getParent().(NEExpr).getParent().(IfStmt).getThen()=target_20
}

predicate func_14(Parameter vtlist_1515, Variable vattrMap_1519, Variable vattrno_1520, SubExpr target_14) {
		target_14.getLeftOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vattrMap_1519
		and target_14.getLeftOperand().(ArrayExpr).getArrayOffset().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vattrno_1520
		and target_14.getLeftOperand().(ArrayExpr).getArrayOffset().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_14.getRightOperand() instanceof Literal
		and target_14.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("list_nth")
		and target_14.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtlist_1515
}

predicate func_15(Variable vnew_tlist_1517, ReturnStmt target_15) {
		target_15.getExpr().(VariableAccess).getTarget()=vnew_tlist_1517
}

predicate func_16(Variable vattrno_1520, Variable vtle_1525, Variable vexpr_1540, ExprStmt target_16) {
		target_16.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vtle_1525
		and target_16.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("makeTargetEntry")
		and target_16.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vexpr_1540
		and target_16.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vattrno_1520
		and target_16.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(FunctionCall).getTarget().hasName("pstrdup")
		and target_16.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="data"
		and target_16.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="attname"
		and target_16.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("Form_pg_attribute")
		and target_16.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(Literal).getValue()="0"
}

predicate func_17(EqualityOperation target_17) {
		target_17.getAnOperand() instanceof ArrayExpr
		and target_17.getAnOperand().(Literal).getValue()="0"
}

predicate func_18(Parameter vtlist_1515, Variable vtle_1525, ExprStmt target_18) {
		target_18.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vtle_1525
		and target_18.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("list_nth")
		and target_18.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtlist_1515
		and target_18.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1) instanceof SubExpr
}

predicate func_19(Parameter vtlist_1515, Variable vtle_1525, Variable vexpr_1540, BlockStmt target_19) {
		target_19.getStmt(2).(IfStmt).getCondition().(EqualityOperation).getAnOperand() instanceof ArrayExpr
		and target_19.getStmt(2).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_19.getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(Literal).getValue()="1"
		and target_19.getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vtle_1525
		and target_19.getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("list_nth")
		and target_19.getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtlist_1515
		and target_19.getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1) instanceof SubExpr
		and target_19.getStmt(2).(IfStmt).getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(Literal).getValue()="1"
		and target_19.getStmt(2).(IfStmt).getElse().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vexpr_1540
		and target_19.getStmt(2).(IfStmt).getElse().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("makeConst")
		and target_19.getStmt(2).(IfStmt).getElse().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(Literal).getValue()="23"
		and target_19.getStmt(2).(IfStmt).getElse().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(Literal).getValue()="0"
		and target_19.getStmt(2).(IfStmt).getElse().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(SizeofTypeOperator).getType() instanceof LongType
		and target_19.getStmt(2).(IfStmt).getElse().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(SizeofTypeOperator).getValue()="4"
		and target_19.getStmt(2).(IfStmt).getElse().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(Literal).getValue()="0"
		and target_19.getStmt(2).(IfStmt).getElse().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(Literal).getValue()="1"
		and target_19.getStmt(2).(IfStmt).getElse().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(6).(Literal).getValue()="1"
}

predicate func_20(Parameter vtlist_1515, Variable vtle_1525, BlockStmt target_20) {
		target_20.getStmt(0).(ExprStmt).getExpr().(Literal).getValue()="1"
		and target_20.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vtle_1525
		and target_20.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("list_nth")
		and target_20.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtlist_1515
		and target_20.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1) instanceof SubExpr
}

from Function func, Parameter vtlist_1515, Variable vnew_tlist_1517, Variable vtupdesc_1518, Variable vattrMap_1519, Variable vattrno_1520, Variable vtle_1525, Variable vexpr_1540, VariableAccess target_0, ExprStmt target_9, RelationalOperation target_10, PostfixIncrExpr target_11, ArrayExpr target_12, SubExpr target_14, ReturnStmt target_15, ExprStmt target_16, EqualityOperation target_17, ExprStmt target_18, BlockStmt target_19, BlockStmt target_20
where
func_0(vtlist_1515, vattrno_1520, target_0)
and not func_1(vnew_tlist_1517, vattrno_1520, vtle_1525, vexpr_1540, target_15, target_14, target_16, func)
and not func_5(vtlist_1515, target_18)
and not func_6(target_19, func)
and not func_7(func)
and not func_8(vnew_tlist_1517)
and func_9(vattrno_1520, target_9)
and func_10(vtupdesc_1518, vattrno_1520, target_19, target_10)
and func_11(vattrno_1520, target_11)
and func_12(vattrMap_1519, vattrno_1520, target_20, target_12)
and func_14(vtlist_1515, vattrMap_1519, vattrno_1520, target_14)
and func_15(vnew_tlist_1517, target_15)
and func_16(vattrno_1520, vtle_1525, vexpr_1540, target_16)
and func_17(target_17)
and func_18(vtlist_1515, vtle_1525, target_18)
and func_19(vtlist_1515, vtle_1525, vexpr_1540, target_19)
and func_20(vtlist_1515, vtle_1525, target_20)
and vtlist_1515.getType().hasName("List *")
and vnew_tlist_1517.getType().hasName("List *")
and vtupdesc_1518.getType().hasName("TupleDesc")
and vattrMap_1519.getType().hasName("AttrNumber *")
and vattrno_1520.getType().hasName("AttrNumber")
and vtle_1525.getType().hasName("TargetEntry *")
and vexpr_1540.getType().hasName("Const *")
and vtlist_1515.getFunction() = func
and vnew_tlist_1517.(LocalVariable).getFunction() = func
and vtupdesc_1518.(LocalVariable).getFunction() = func
and vattrMap_1519.(LocalVariable).getFunction() = func
and vattrno_1520.(LocalVariable).getFunction() = func
and vtle_1525.(LocalVariable).getFunction() = func
and vexpr_1540.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
