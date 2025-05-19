//merger sort

// const arr= [2,4,1,45,22,99,12,34,44,5555]


function mergeSort(arr){
    if(arr.length <= 1) return arr
    const mid =Math.floor(arr.length/2)
    const arr1= mergeSort(arr.slice(0,mid))
    const arr2= mergeSort(arr.slice(mid))
    
    return merge(arr1,arr2);
    
}

function merge(arr1, arr2){
    let result=[]
    let i=0;
    let j=0;
    
    while(i<arr1.length && j<arr2.length){
        if(arr1[i]<arr2[j]){
            result.push(arr1[i])
            i++;
        }else{
            result.push(arr2[j])
            j++;
        }
        
    }
    
        while(i < arr1.length){
        result.push(arr1[i])
        i++;
        }
    while(j<arr2.length){
        result.push(arr2[j])
        j++;
    }
    return result;
}

console.log(mergeSort([2,4,1,45,22,99,12,34,44,5555]))