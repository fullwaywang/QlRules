/**
 * @name curl-894f6ec730597eb243618d33cc84d71add8d6a8a-suboption
 * @id cpp/curl/894f6ec730597eb243618d33cc84d71add8d6a8a/suboption
 * @description curl-894f6ec730597eb243618d33cc84d71add8d6a8a-suboption CVE-2021-22925
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(StringLiteral target_0 |
		target_0.getValue()="%127[^,],%127s"
		and not target_0.getValue()="%127[^,]%1[,]%127s"
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Variable vtmplen_920) {
	exists(VariableAccess target_1 |
		target_1.getTarget()=vtmplen_920)
}

predicate func_2(Variable vtemp_878, Variable vlen_880, Variable vtmplen_920) {
	exists(DeclStmt target_2 |
		target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vlen_880
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vtmplen_920
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(SubExpr).getLeftOperand().(SizeofExprOperator).getExprOperand().(VariableAccess).getTarget()=vtemp_878
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(SubExpr).getRightOperand().(Literal).getValue()="6")
}

predicate func_3(Variable vtemp_878, Variable vlen_880, Variable vtmplen_920) {
	exists(DeclStmt target_3 |
		target_3.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(StringLiteral).getValue()=""
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vlen_880
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vtmplen_920
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(SubExpr).getLeftOperand().(SizeofExprOperator).getExprOperand().(VariableAccess).getTarget()=vtemp_878
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(SubExpr).getRightOperand().(Literal).getValue()="6")
}

predicate func_4(Variable vvarval_883) {
	exists(AssignExpr target_4 |
		target_4.getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vvarval_883
		and target_4.getLValue().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_4.getRValue().(Literal).getValue()="0")
}

predicate func_5(Variable vv_877, Variable vvarname_882, Variable vvarval_883) {
	exists(AssignExpr target_5 |
		target_5.getLValue().(VariableAccess).getType().hasName("int")
		and target_5.getRValue().(FunctionCall).getTarget().hasName("sscanf")
		and target_5.getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="data"
		and target_5.getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vv_877
		and target_5.getRValue().(FunctionCall).getArgument(1).(StringLiteral).getValue()="%127[^,]%1[,]%127s"
		and target_5.getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vvarname_882
		and target_5.getRValue().(FunctionCall).getArgument(3).(VariableAccess).getType().hasName("char[2]")
		and target_5.getRValue().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vvarval_883)
}

predicate func_10(Variable vtemp_878, Variable vlen_880, Variable vvarname_882) {
	exists(ExprStmt target_10 |
		target_10.getExpr().(AssignAddExpr).getLValue().(VariableAccess).getTarget()=vlen_880
		and target_10.getExpr().(AssignAddExpr).getRValue().(FunctionCall).getTarget().hasName("curl_msnprintf")
		and target_10.getExpr().(AssignAddExpr).getRValue().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vtemp_878
		and target_10.getExpr().(AssignAddExpr).getRValue().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getType().hasName("size_t")
		and target_10.getExpr().(AssignAddExpr).getRValue().(FunctionCall).getArgument(1).(SubExpr).getLeftOperand().(SizeofExprOperator).getExprOperand().(VariableAccess).getTarget()=vtemp_878
		and target_10.getExpr().(AssignAddExpr).getRValue().(FunctionCall).getArgument(1).(SubExpr).getRightOperand().(VariableAccess).getTarget()=vlen_880
		and target_10.getExpr().(AssignAddExpr).getRValue().(FunctionCall).getArgument(2).(StringLiteral).getValue()="%c%s"
		and target_10.getExpr().(AssignAddExpr).getRValue().(FunctionCall).getArgument(3).(Literal).getValue()="0"
		and target_10.getExpr().(AssignAddExpr).getRValue().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vvarname_882
		and target_10.getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getType().hasName("int")
		and target_10.getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="1")
}

predicate func_12(Variable vlen_880) {
	exists(IfStmt target_12 |
		target_12.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getType().hasName("int")
		and target_12.getCondition().(RelationalOperation).getLesserOperand() instanceof Literal
		and target_12.getThen().(ExprStmt).getExpr().(AssignAddExpr).getLValue().(VariableAccess).getTarget()=vlen_880
		and target_12.getThen().(ExprStmt).getExpr().(AssignAddExpr).getRValue() instanceof FunctionCall
		and target_12.getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getType().hasName("int")
		and target_12.getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="1")
}

predicate func_13(Variable vtemp_878, Variable vlen_880, Variable vvarname_882, Variable vvarval_883) {
	exists(FunctionCall target_13 |
		target_13.getTarget().hasName("curl_msnprintf")
		and target_13.getArgument(0).(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vtemp_878
		and target_13.getArgument(0).(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vlen_880
		and target_13.getArgument(1).(SubExpr).getLeftOperand().(SizeofExprOperator).getValue()="2048"
		and target_13.getArgument(1).(SubExpr).getLeftOperand().(SizeofExprOperator).getExprOperand().(VariableAccess).getTarget()=vtemp_878
		and target_13.getArgument(1).(SubExpr).getRightOperand().(VariableAccess).getTarget()=vlen_880
		and target_13.getArgument(2).(StringLiteral).getValue()="%c%s%c%s"
		and target_13.getArgument(3).(Literal).getValue()="0"
		and target_13.getArgument(4).(VariableAccess).getTarget()=vvarname_882
		and target_13.getArgument(5).(Literal).getValue()="1"
		and target_13.getArgument(6).(VariableAccess).getTarget()=vvarval_883)
}

predicate func_15(Function func) {
	exists(Literal target_15 |
		target_15.getValue()="2"
		and target_15.getEnclosingFunction() = func)
}

predicate func_16(Variable vtemp_878, Variable vlen_880) {
	exists(ArrayExpr target_16 |
		target_16.getArrayBase().(VariableAccess).getTarget()=vtemp_878
		and target_16.getArrayOffset().(VariableAccess).getTarget()=vlen_880)
}

predicate func_17(Variable vlen_880, Variable vtmplen_920) {
	exists(AssignAddExpr target_17 |
		target_17.getLValue().(VariableAccess).getTarget()=vlen_880
		and target_17.getRValue().(VariableAccess).getTarget()=vtmplen_920)
}

from Function func, Variable vv_877, Variable vtemp_878, Variable vlen_880, Variable vvarname_882, Variable vvarval_883, Variable vtmplen_920
where
func_0(func)
and func_1(vtmplen_920)
and not func_2(vtemp_878, vlen_880, vtmplen_920)
and not func_3(vtemp_878, vlen_880, vtmplen_920)
and not func_4(vvarval_883)
and not func_5(vv_877, vvarname_882, vvarval_883)
and not func_10(vtemp_878, vlen_880, vvarname_882)
and not func_12(vlen_880)
and func_13(vtemp_878, vlen_880, vvarname_882, vvarval_883)
and func_15(func)
and vv_877.getType().hasName("curl_slist *")
and vtemp_878.getType().hasName("unsigned char[2048]")
and vlen_880.getType().hasName("size_t")
and func_16(vtemp_878, vlen_880)
and func_17(vlen_880, vtmplen_920)
and vvarname_882.getType().hasName("char[128]")
and vvarval_883.getType().hasName("char[128]")
and vtmplen_920.getType().hasName("size_t")
and vv_877.getParentScope+() = func
and vtemp_878.getParentScope+() = func
and vlen_880.getParentScope+() = func
and vvarname_882.getParentScope+() = func
and vvarval_883.getParentScope+() = func
and vtmplen_920.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
