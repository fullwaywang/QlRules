/**
 * @name libtiff-83a4b92815ea04969d494416eaae3d4c6b338e4a-loadImage
 * @id cpp/libtiff/83a4b92815ea04969d494416eaae3d4c6b338e4a/loadImage
 * @description libtiff-83a4b92815ea04969d494416eaae3d4c6b338e4a-tools/tiffcrop.c-loadImage CVE-2016-9533
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_2(Variable vbuffsize_5767, BlockStmt target_10, AddExpr target_11, RelationalOperation target_8) {
	exists(RelationalOperation target_2 |
		 (target_2 instanceof GTExpr or target_2 instanceof LTExpr)
		and target_2.getGreaterOperand().(VariableAccess).getTarget()=vbuffsize_5767
		and target_2.getLesserOperand().(SubExpr).getValue()="4294967292"
		and target_2.getParent().(IfStmt).getThen()=target_10
		and target_11.getAnOperand().(VariableAccess).getLocation().isBefore(target_2.getGreaterOperand().(VariableAccess).getLocation())
		and target_2.getGreaterOperand().(VariableAccess).getLocation().isBefore(target_8.getGreaterOperand().(VariableAccess).getLocation()))
}

predicate func_3(RelationalOperation target_8, Function func) {
	exists(ExprStmt target_3 |
		target_3.getExpr().(FunctionCall).getTarget().hasName("TIFFError")
		and target_3.getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()="loadImage"
		and target_3.getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="Unable to allocate/reallocate read buffer"
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_3
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_8
		and target_3.getEnclosingFunction() = func)
}

predicate func_4(RelationalOperation target_8, Function func) {
	exists(ReturnStmt target_4 |
		target_4.getExpr().(UnaryMinusExpr).getValue()="-1"
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_4
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_8
		and target_4.getEnclosingFunction() = func)
}

predicate func_5(Variable vbuffsize_5767, Variable vread_buff_5770, Variable vnew_buff_5771, NotExpr target_12, RelationalOperation target_8, AddExpr target_13, ExprStmt target_9, NotExpr target_14) {
	exists(IfStmt target_5 |
		target_5.getCondition() instanceof RelationalOperation
		and target_5.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vbuffsize_5767
		and target_5.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getValue()="4294967292"
		and target_5.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("TIFFError")
		and target_5.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()="loadImage"
		and target_5.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="Unable to allocate/reallocate read buffer"
		and target_5.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1"
		and target_5.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vnew_buff_5771
		and target_5.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("_TIFFrealloc")
		and target_5.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vread_buff_5770
		and target_5.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(AddExpr).getAnOperand().(VariableAccess).getTarget()=vbuffsize_5767
		and target_5.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(AddExpr).getAnOperand().(Literal).getValue()="3"
		and target_5.getThen().(BlockStmt).getStmt(2).(IfStmt).getCondition().(NotExpr).getOperand().(VariableAccess).getTarget()=vnew_buff_5771
		and target_5.getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("free")
		and target_5.getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vread_buff_5770
		and target_5.getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vread_buff_5770
		and target_5.getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("_TIFFmalloc")
		and target_5.getThen().(BlockStmt).getStmt(2).(IfStmt).getElse().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vread_buff_5770
		and target_5.getThen().(BlockStmt).getStmt(2).(IfStmt).getElse().(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vnew_buff_5771
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getElse().(BlockStmt).getStmt(0)=target_5
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_12
		and target_8.getGreaterOperand().(VariableAccess).getLocation().isBefore(target_5.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation())
		and target_5.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_13.getAnOperand().(VariableAccess).getLocation())
		and target_9.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_5.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_5.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_14.getOperand().(VariableAccess).getLocation()))
}

/*predicate func_6(Variable vbuffsize_5767, RelationalOperation target_8, AddExpr target_15) {
	exists(IfStmt target_6 |
		target_6.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vbuffsize_5767
		and target_6.getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getValue()="4294967292"
		and target_6.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("TIFFError")
		and target_6.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()="loadImage"
		and target_6.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="Unable to allocate/reallocate read buffer"
		and target_6.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1"
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_6
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_8
		and target_6.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_15.getAnOperand().(VariableAccess).getLocation()))
}

*/
predicate func_8(Variable vbuffsize_5767, Variable vprev_readsize_5773, BlockStmt target_10, RelationalOperation target_8) {
		 (target_8 instanceof GTExpr or target_8 instanceof LTExpr)
		and target_8.getLesserOperand().(VariableAccess).getTarget()=vprev_readsize_5773
		and target_8.getGreaterOperand().(VariableAccess).getTarget()=vbuffsize_5767
		and target_8.getParent().(IfStmt).getThen()=target_10
}

predicate func_9(Variable vbuffsize_5767, Variable vread_buff_5770, NotExpr target_12, ExprStmt target_9) {
		target_9.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vread_buff_5770
		and target_9.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("_TIFFmalloc")
		and target_9.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(AddExpr).getAnOperand().(VariableAccess).getTarget()=vbuffsize_5767
		and target_9.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(AddExpr).getAnOperand().(Literal).getValue()="3"
		and target_9.getParent().(IfStmt).getCondition()=target_12
}

predicate func_10(Variable vbuffsize_5767, Variable vread_buff_5770, Variable vnew_buff_5771, BlockStmt target_10) {
		target_10.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vnew_buff_5771
		and target_10.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("_TIFFrealloc")
		and target_10.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vread_buff_5770
		and target_10.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(AddExpr).getAnOperand().(VariableAccess).getTarget()=vbuffsize_5767
		and target_10.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(AddExpr).getAnOperand().(Literal).getValue()="3"
}

predicate func_11(Variable vbuffsize_5767, AddExpr target_11) {
		target_11.getAnOperand().(VariableAccess).getTarget()=vbuffsize_5767
		and target_11.getAnOperand().(Literal).getValue()="3"
}

predicate func_12(Variable vread_buff_5770, NotExpr target_12) {
		target_12.getOperand().(VariableAccess).getTarget()=vread_buff_5770
}

predicate func_13(Variable vbuffsize_5767, AddExpr target_13) {
		target_13.getAnOperand().(VariableAccess).getTarget()=vbuffsize_5767
		and target_13.getAnOperand().(Literal).getValue()="3"
}

predicate func_14(Variable vread_buff_5770, NotExpr target_14) {
		target_14.getOperand().(VariableAccess).getTarget()=vread_buff_5770
}

predicate func_15(Variable vbuffsize_5767, AddExpr target_15) {
		target_15.getAnOperand().(VariableAccess).getTarget()=vbuffsize_5767
		and target_15.getAnOperand().(Literal).getValue()="3"
}

from Function func, Variable vbuffsize_5767, Variable vread_buff_5770, Variable vnew_buff_5771, Variable vprev_readsize_5773, RelationalOperation target_8, ExprStmt target_9, BlockStmt target_10, AddExpr target_11, NotExpr target_12, AddExpr target_13, NotExpr target_14, AddExpr target_15
where
not func_2(vbuffsize_5767, target_10, target_11, target_8)
and not func_3(target_8, func)
and not func_4(target_8, func)
and not func_5(vbuffsize_5767, vread_buff_5770, vnew_buff_5771, target_12, target_8, target_13, target_9, target_14)
and func_8(vbuffsize_5767, vprev_readsize_5773, target_10, target_8)
and func_9(vbuffsize_5767, vread_buff_5770, target_12, target_9)
and func_10(vbuffsize_5767, vread_buff_5770, vnew_buff_5771, target_10)
and func_11(vbuffsize_5767, target_11)
and func_12(vread_buff_5770, target_12)
and func_13(vbuffsize_5767, target_13)
and func_14(vread_buff_5770, target_14)
and func_15(vbuffsize_5767, target_15)
and vbuffsize_5767.getType().hasName("uint32")
and vread_buff_5770.getType().hasName("unsigned char *")
and vnew_buff_5771.getType().hasName("unsigned char *")
and vprev_readsize_5773.getType().hasName("uint32")
and vbuffsize_5767.(LocalVariable).getFunction() = func
and vread_buff_5770.(LocalVariable).getFunction() = func
and vnew_buff_5771.(LocalVariable).getFunction() = func
and vprev_readsize_5773.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
