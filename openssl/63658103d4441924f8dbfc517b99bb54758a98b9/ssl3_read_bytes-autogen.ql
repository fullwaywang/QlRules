import cpp

predicate func_0(Function func) {
	exists(Literal target_0 |
		target_0.getValue()="1181"
		and not target_0.getValue()="1185"
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Function func) {
	exists(Literal target_1 |
		target_1.getValue()="1195"
		and not target_1.getValue()="1199"
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(Function func) {
	exists(Literal target_2 |
		target_2.getValue()="1255"
		and not target_2.getValue()="1259"
		and target_2.getEnclosingFunction() = func)
}

predicate func_3(Function func) {
	exists(Literal target_3 |
		target_3.getValue()="1273"
		and not target_3.getValue()="1277"
		and target_3.getEnclosingFunction() = func)
}

predicate func_4(Function func) {
	exists(Literal target_4 |
		target_4.getValue()="1348"
		and not target_4.getValue()="1352"
		and target_4.getEnclosingFunction() = func)
}

predicate func_5(Function func) {
	exists(Literal target_5 |
		target_5.getValue()="1366"
		and not target_5.getValue()="1370"
		and target_5.getEnclosingFunction() = func)
}

predicate func_6(Function func) {
	exists(Literal target_6 |
		target_6.getValue()="1378"
		and not target_6.getValue()="1382"
		and target_6.getEnclosingFunction() = func)
}

predicate func_7(Function func) {
	exists(Literal target_7 |
		target_7.getValue()="1387"
		and not target_7.getValue()="1391"
		and target_7.getEnclosingFunction() = func)
}

predicate func_8(Function func) {
	exists(Literal target_8 |
		target_8.getValue()="1404"
		and not target_8.getValue()="1408"
		and target_8.getEnclosingFunction() = func)
}

predicate func_9(Function func) {
	exists(Literal target_9 |
		target_9.getValue()="1423"
		and not target_9.getValue()="1427"
		and target_9.getEnclosingFunction() = func)
}

predicate func_10(Function func) {
	exists(Literal target_10 |
		target_10.getValue()="1459"
		and not target_10.getValue()="1463"
		and target_10.getEnclosingFunction() = func)
}

predicate func_11(Function func) {
	exists(Literal target_11 |
		target_11.getValue()="1470"
		and not target_11.getValue()="1474"
		and target_11.getEnclosingFunction() = func)
}

predicate func_12(Function func) {
	exists(Literal target_12 |
		target_12.getValue()="1485"
		and not target_12.getValue()="1489"
		and target_12.getEnclosingFunction() = func)
}

predicate func_16(Variable vrr, Parameter vpeek, Variable vn, Parameter vs) {
	exists(NotExpr target_16 |
		target_16.getType().hasName("int")
		and target_16.getOperand().(VariableAccess).getTarget()=vpeek
		and target_16.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignSubExpr).getLValue().(PointerFieldAccess).getTarget().getName()="length"
		and target_16.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignSubExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrr
		and target_16.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignSubExpr).getRValue().(VariableAccess).getTarget()=vn
		and target_16.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignAddExpr).getLValue().(PointerFieldAccess).getTarget().getName()="off"
		and target_16.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignAddExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrr
		and target_16.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignAddExpr).getRValue().(VariableAccess).getTarget()=vn
		and target_16.getParent().(IfStmt).getThen().(BlockStmt).getStmt(2).(IfStmt).getCondition().(EQExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="length"
		and target_16.getParent().(IfStmt).getThen().(BlockStmt).getStmt(2).(IfStmt).getCondition().(EQExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrr
		and target_16.getParent().(IfStmt).getThen().(BlockStmt).getStmt(2).(IfStmt).getCondition().(EQExpr).getRightOperand().(Literal).getValue()="0"
		and target_16.getParent().(IfStmt).getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="rstate"
		and target_16.getParent().(IfStmt).getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="rlayer"
		and target_16.getParent().(IfStmt).getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs
		and target_16.getParent().(IfStmt).getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="240"
		and target_16.getParent().(IfStmt).getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="off"
		and target_16.getParent().(IfStmt).getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrr
		and target_16.getParent().(IfStmt).getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_16.getParent().(IfStmt).getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="read"
		and target_16.getParent().(IfStmt).getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrr
		and target_16.getParent().(IfStmt).getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="1")
}

predicate func_17(Variable vrr, Variable valert_level) {
	exists(ExprStmt target_17 |
		target_17.getExpr().(AssignExpr).getType().hasName("unsigned int")
		and target_17.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="read"
		and target_17.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getType().hasName("unsigned int")
		and target_17.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrr
		and target_17.getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
		and target_17.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EQExpr).getType().hasName("int")
		and target_17.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EQExpr).getLeftOperand().(VariableAccess).getTarget()=valert_level
		and target_17.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EQExpr).getRightOperand().(Literal).getValue()="1")
}

from Function func, Variable vrr, Variable valert_level, Parameter vpeek, Variable vn, Parameter vs
where
func_0(func)
and func_1(func)
and func_2(func)
and func_3(func)
and func_4(func)
and func_5(func)
and func_6(func)
and func_7(func)
and func_8(func)
and func_9(func)
and func_10(func)
and func_11(func)
and func_12(func)
and func_16(vrr, vpeek, vn, vs)
and func_17(vrr, valert_level)
and vrr.getType().hasName("SSL3_RECORD *")
and valert_level.getType().hasName("int")
and vpeek.getType().hasName("int")
and vn.getType().hasName("unsigned int")
and vs.getType().hasName("SSL *")
and vrr.getParentScope+() = func
and valert_level.getParentScope+() = func
and vpeek.getParentScope+() = func
and vn.getParentScope+() = func
and vs.getParentScope+() = func
select func, vrr, valert_level, vpeek, vn, vs
