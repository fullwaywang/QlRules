/**
 * @name vim-4d97a565ae8be0d4debba04ebd2ac3e75a0c8010-parse_cmd_address
 * @id cpp/vim/4d97a565ae8be0d4debba04ebd2ac3e75a0c8010/parse-cmd-address
 * @description vim-4d97a565ae8be0d4debba04ebd2ac3e75a0c8010-src/ex_docmd.c-parse_cmd_address CVE-2022-1927
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, Literal target_0) {
		target_0.getValue()="0"
		and not target_0.getValue()="1"
		and target_0.getParent().(ReturnStmt).getParent().(BlockStmt).getStmt(19) instanceof ReturnStmt
		and target_0.getEnclosingFunction() = func
}

predicate func_1(EqualityOperation target_21, Function func) {
	exists(GotoStmt target_1 |
		target_1.toString() = "goto ..."
		and target_1.getName() ="theend"
		and target_1.getParent().(IfStmt).getCondition()=target_21
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(RelationalOperation target_22, Function func) {
	exists(GotoStmt target_2 |
		target_2.toString() = "goto ..."
		and target_2.getName() ="theend"
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getElse().(BlockStmt).getStmt(1)=target_2
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_22
		and target_2.getEnclosingFunction() = func)
}

predicate func_3(PointerFieldAccess target_23, Function func) {
	exists(GotoStmt target_3 |
		target_3.toString() = "goto ..."
		and target_3.getName() ="theend"
		and target_3.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_23
		and target_3.getEnclosingFunction() = func)
}

predicate func_4(EqualityOperation target_24, Function func) {
	exists(GotoStmt target_4 |
		target_4.toString() = "goto ..."
		and target_4.getName() ="theend"
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_4
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_24
		and target_4.getEnclosingFunction() = func)
}

predicate func_5(EqualityOperation target_25, Function func) {
	exists(GotoStmt target_5 |
		target_5.toString() = "goto ..."
		and target_5.getName() ="theend"
		and target_5.getParent().(IfStmt).getCondition()=target_25
		and target_5.getEnclosingFunction() = func)
}

predicate func_6(EqualityOperation target_26, Function func) {
	exists(GotoStmt target_6 |
		target_6.toString() = "goto ..."
		and target_6.getName() ="theend"
		and target_6.getParent().(IfStmt).getCondition()=target_26
		and target_6.getEnclosingFunction() = func)
}

predicate func_7(NotExpr target_27, Function func) {
	exists(ExprStmt target_7 |
		target_7.getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("int")
		and target_7.getExpr().(AssignExpr).getRValue() instanceof Literal
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(2)=target_7
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_27
		and target_7.getEnclosingFunction() = func)
}

predicate func_8(Function func) {
	exists(ExprStmt target_8 |
		target_8.getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("int")
		and target_8.getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
		and (func.getEntryPoint().(BlockStmt).getStmt(6)=target_8 or func.getEntryPoint().(BlockStmt).getStmt(6).getFollowingStmt()=target_8))
}

predicate func_10(Function func) {
	exists(IfStmt target_10 |
		target_10.getCondition().(VariableAccess).getType().hasName("int")
		and target_10.getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("check_cursor")
		and (func.getEntryPoint().(BlockStmt).getStmt(8)=target_10 or func.getEntryPoint().(BlockStmt).getStmt(8).getFollowingStmt()=target_10))
}

predicate func_15(EqualityOperation target_21, Function func, ReturnStmt target_15) {
		target_15.getExpr() instanceof Literal
		and target_15.getParent().(IfStmt).getCondition()=target_21
		and target_15.getEnclosingFunction() = func
}

predicate func_16(RelationalOperation target_22, Function func, ReturnStmt target_16) {
		target_16.getExpr() instanceof Literal
		and target_16.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_22
		and target_16.getEnclosingFunction() = func
}

predicate func_17(PointerFieldAccess target_23, Function func, ReturnStmt target_17) {
		target_17.getExpr() instanceof Literal
		and target_17.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_23
		and target_17.getEnclosingFunction() = func
}

predicate func_18(EqualityOperation target_24, Function func, ReturnStmt target_18) {
		target_18.getExpr().(Literal).getValue()="0"
		and target_18.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_24
		and target_18.getEnclosingFunction() = func
}

predicate func_19(EqualityOperation target_25, Function func, ReturnStmt target_19) {
		target_19.getExpr().(Literal).getValue()="0"
		and target_19.getParent().(IfStmt).getCondition()=target_25
		and target_19.getEnclosingFunction() = func
}

predicate func_20(EqualityOperation target_26, Function func, ReturnStmt target_20) {
		target_20.getExpr().(Literal).getValue()="0"
		and target_20.getParent().(IfStmt).getCondition()=target_26
		and target_20.getEnclosingFunction() = func
}

predicate func_21(EqualityOperation target_21) {
		target_21.getAnOperand().(PointerFieldAccess).getTarget().getName()="cmd"
		and target_21.getAnOperand().(Literal).getValue()="0"
}

predicate func_22(RelationalOperation target_22) {
		 (target_22 instanceof GTExpr or target_22 instanceof LTExpr)
		and target_22.getLesserOperand().(PointerFieldAccess).getTarget().getName()="cmdidx"
		and target_22.getGreaterOperand().(Literal).getValue()="0"
}

predicate func_23(PointerFieldAccess target_23) {
		target_23.getTarget().getName()="addr_type"
}

predicate func_24(EqualityOperation target_24) {
		target_24.getAnOperand().(PointerFieldAccess).getTarget().getName()="addr_type"
}

predicate func_25(EqualityOperation target_25) {
		target_25.getAnOperand().(FunctionCall).getTarget().hasName("check_mark")
		and target_25.getAnOperand().(Literal).getValue()="0"
}

predicate func_26(EqualityOperation target_26) {
		target_26.getAnOperand().(FunctionCall).getTarget().hasName("check_mark")
		and target_26.getAnOperand().(Literal).getValue()="0"
}

predicate func_27(NotExpr target_27) {
		target_27.getOperand().(PointerFieldAccess).getTarget().getName()="skip"
}

from Function func, Literal target_0, ReturnStmt target_15, ReturnStmt target_16, ReturnStmt target_17, ReturnStmt target_18, ReturnStmt target_19, ReturnStmt target_20, EqualityOperation target_21, RelationalOperation target_22, PointerFieldAccess target_23, EqualityOperation target_24, EqualityOperation target_25, EqualityOperation target_26, NotExpr target_27
where
func_0(func, target_0)
and not func_1(target_21, func)
and not func_2(target_22, func)
and not func_3(target_23, func)
and not func_4(target_24, func)
and not func_5(target_25, func)
and not func_6(target_26, func)
and not func_7(target_27, func)
and not func_8(func)
and not func_10(func)
and func_15(target_21, func, target_15)
and func_16(target_22, func, target_16)
and func_17(target_23, func, target_17)
and func_18(target_24, func, target_18)
and func_19(target_25, func, target_19)
and func_20(target_26, func, target_20)
and func_21(target_21)
and func_22(target_22)
and func_23(target_23)
and func_24(target_24)
and func_25(target_25)
and func_26(target_26)
and func_27(target_27)
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
